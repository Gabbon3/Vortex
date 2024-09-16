import Buffer from './Buffer.js';
/**
 * Cifrario a flusso
 * ChaCha20 like
 */
class Vortex extends Buffer {
    constructor() { super(); }
    static key_size = 32; // byte
    static nonche_size = 24; // byte
    /**
     * Costanti per Vortex
     */
    // F = Firma dell'algoritmo ("+V0rt3x^")
    static F = new Uint32Array([1915770411, 1584935796]);
    /**
     * costanti per poly 1305
     */
    static Mod = 1361129467683753853853498429727072845819n; // (2n ** 130n) - 5n;
    static Mask = 340282366920938463463374607431768211455n; // (2n ** 128n) - 1n;
    /**
     * Restituisce dei bytes casuali
     * @param {int} b numero di bytes da restituire
     * @param {boolean} as_base64 defalt su false per restituire i byte se no restituisce la stringa in base 64
     * @returns {Uint8Array | String}
     */
    static random_bytes(b, as_base64 = false) {
        if (b < 1) {
            return null;
        }
        // ---
        const bytes = crypto.getRandomValues(new Uint8Array(b));
        return as_base64 ? this.base64._bytes(bytes) : bytes;
    }
    /**
     * Calcola il contatore eseguendo operazioni non lineari sui bit
     * @param {Uint32Array} KN sta per K chiave N nonche, in base a quello che viene passato viene eseguito lo xor di tutte le parole che lo compongono
     * @returns {Int32Array}
    */
    static counter(K, N) {
        // --
        N = super.merge([N, this.F], 32);
        // -- numero di iterazioni
        const L = 16;
        // -- contatore da restituire
        const C = new Uint32Array([K[0], N[0]]);
        let m = 0;
        let s = 7; // shift
        for (let i = 1; i < L; i++) {
            m = i % 8;
            // ---
            C[0] -= C[1];
            C[0] ^= C[1];
            // --
            C[0] += i % 2 ? K[m] : N[m];
            C[1] ^= i % 2 ? N[m] : K[m];
            // --
            s = (i * 7) % 32;
            C[0] = (C[0] << s) | (C[0] >>> (32 - s));
            C[1] = (C[1] << s) | (C[1] >>> (32 - s));
            // --
            C[0] ^= i % 2 ? N[m] : K[m];
            C[1] += i % 2 ? K[m] : N[m];
            // --
            C[1] -= C[0];
            C[1] ^= C[0];
            // ---
            C[0] &= 0xFFFFFFFF;
            C[1] &= 0xFFFFFFFF;
        }
        // ---
        return C;
    }
    /**
     * Mescola i dati utilizzando calcoli aritmetici semplici
     * @param {Uint32Array} B blocco di dati
     * @param {int} a 
     * @param {int} b 
     * @param {int} c 
     * @param {int} d 
     */
    static mix(B, a, b, c, d) {
        // -- STEP 1
        B[a] += B[b];
        B[b] -= B[c];
        B[c] = (B[c] << 11) | (B[c] >>> 21);
        B[d] ^= B[a];
        // -- STEP 2
        B[a] -= B[c];
        B[b] = (B[b] << 17) | (B[b] >>> 15);
        B[c] ^= B[d];
        B[d] += B[b];
        // -- STEP 3
        B[a] = (B[a] << 13) | (B[a] >>> 19);
        B[b] ^= B[d];
        B[c] += B[a];
        B[d] -= B[c];
        // -- STEP 4 
        B[a] ^= B[d];
        B[b] += B[c];
        B[c] -= B[b];
        B[d] = (B[d] << 7) | (B[d] >>> 25);
    }
    /**
     * Genera (cucina) lo stream basandosi su chiave e nonche
     * inizializza un blocco da 16 parole (64 byte) e lo processa 20 volte per colonne e diagonali
     * @param {Uint32Array} B 16 parole
     */
    static cook(B) {
        // ---
        for (let i = 0; i < 20; i++) {
            this.mix(B, 0, 4, 8, 12);
            this.mix(B, 1, 5, 9, 13);
            this.mix(B, 2, 6, 10, 14);
            this.mix(B, 3, 7, 11, 15);
            // ---
            this.mix(B, 0, 5, 10, 15);
            this.mix(B, 1, 6, 11, 12);
            this.mix(B, 2, 7, 8, 13);
            this.mix(B, 3, 4, 9, 14);
        }
    }
    /**
     * Combina la chiave il nonce e il contatore per ottenere una sequenza
     * byte lunga L (parametro)
     * @param {Uint32Array} K chiave 8
     * @param {Uint32Array} N nonce 6
     * @param {Uint32Array} C contatore 2
     * @param {int} L numero di byte da ottenere in uscita
     */
    static keystream(K, N, C, L) {
        // -- NW = Number of Words = numero di parole da ottenere
        const NW = Math.ceil(L / 4);
        // numero di byte generati
        let GL = 0;
        // -- inizializzo il keystream
        const KS = new Uint32Array(L);
        // -- usato per il counter
        let c = true;
        const B = new Uint32Array(16);
        // ---
        while (GL < NW) {
            B.set(K); // --+ chiave
            B.set(N, 8); // --+ nonce
            B.set(C, 14); // --+ contatore
            // ---
            this.cook(B);
            // -- wtc = word (32 bit) to copy
            const wtc = Math.min(B.length, NW - GL);
            // ---
            KS.set(B.subarray(0, wtc), GL);
            // ---
            GL += 16;
            c ? C[0]++ : C[1]++;
            c = !c;
        }
        // ---
        return new Uint8Array(KS.buffer, 0, L);
    }
    /**
     * Cifra utilizzando Vortex
     * @param {ArrayBuffer} M testo
     * @param {ArrayBuffer} K chiave base 64
     * @param {ArrayBuffer} N nonce base 64
     */
    static encrypt(M, K, N = null) {
        if (!(M instanceof ArrayBuffer && K instanceof ArrayBuffer)) throw new TypeError("I parametri devono essere ArrayBuffer");
        // --- controlli sulle lunghezze
        if (K.byteLength !== 32) throw new Error("la Chiave deve essere di 32 byte");
        if (N && N.byteLength !== 24) throw new Error("il Nonche deve essere di 24 byte");
        // ---
        K = new Uint32Array(K);
        N = new Uint32Array(N ?? this.random_bytes(this.nonche_size).buffer);
        M = new Uint8Array(M);
        // ---
        const L = M.length;
        // -- contatore
        const C = this.counter(K, N);
        // ---
        const KS = this.keystream(K, N, C, L);
        // ---
        let EM = new Uint8Array(L);
        for (let i = 0; i < L; i++) {
            EM[i] = M[i] ^ KS[i];
        }
        // -- KP = Chiave Poly
        const KP = this.poly_key(K, N, C);
        // -- genero il tag di autenticazione
        const T = this.poly_1305(M, KP); // tag autenticazione
        // -- concateno la firma
        EM = super.merge([EM, T], 8);
        // ---
        return {
            EM: EM.buffer,
            N: N
        };
    }
    /**
     * Decifra utilizzando Vortex
     * @param {ArrayBuffer} EMT testo cifrato + tag autenticazione
     * @param {ArrayBuffer} K chiave
     * @param {ArrayBuffer} N nonce
     */
    static decrypt(EMT, K, N) {
        if (!(EMT instanceof ArrayBuffer && K instanceof ArrayBuffer && N instanceof ArrayBuffer)) throw new TypeError("I parametri devono essere ArrayBuffer");
        // ---
        EMT = new Uint8Array(EMT);
        // -- estraggo il tag dal messaggio
        const T = EMT.subarray(EMT.length - 16); // tag autenticazione
        const EM = EMT.subarray(0, EMT.length - 16);
        // --- controlli sulle lunghezze
        if (K.byteLength !== 32) throw new Error("la Chiave deve essere di 32 byte");
        if (N.byteLength !== 24) throw new Error("il Nonche deve essere di 24 byte");
        // ---
        K = new Uint32Array(K8.buffer);
        N = new Uint32Array(N8.buffer);
        // ---
        const L = EM.length;
        // -- contatore
        const C = this.counter(K, N);
        // ---
        const KS = this.keystream(K, N, C, L);
        // ---
        let M = new Uint8Array(L);
        for (let i = 0; i < L; i++) {
            M[i] = EM[i] ^ KS[i];
        }
        // -- KP = Chiave Poly
        const KP = this.poly_key(K, N, C);
        // -- verifico il tag
        const TD = this.poly_1305(M, KP); // Tag generato dal testo appena Decifrato
        if (Buffer.compare(TD, T) === false) return null;
        // ---
        return M.buffer;
    }
    /**
     * Genera la chiave per l'autenticazione
     * @param {Uint32Array} K chiave 
     * @param {Uint32Array} N nonce
     * @param {Uint32Array} C contatore
     * @returns {Uint32Array}
     */
    static poly_key(K, N, C) {
        const B = super.merge([K, N, C], 32);
        // ---
        this.cook(B);
        // ---
        return new Uint8Array(B.slice(0, 8).buffer);
    }
    /**
     * Genera un tag utilizzando Poly1305
     * @param {Uint8Array} M messaggio
     * @param {Uint8Array} K chiave
     */
    static poly_1305(M, K) {
        M = new Uint16Array(M.buffer);
        const L = M.length;
        // ---
        const r = K.subarray(0, 16);
        const s = K.subarray(16);
        const R = super.bigint._bytes(r);
        const S = super.bigint._bytes(s);
        // ---
        let acc = 0n;
        // ---
        for (let i = 0; i < L; i++) {
            const n = BigInt(M[i]);
            acc = (acc + n) * R % this.Mod;
        }
        // ---
        acc = (acc + S) % this.Mod;
        // -- applico la maschera per ottenere 128 bit
        acc &= this.Mask;
        // ---
        return super.bigint.bytes_(acc);
    }
}

export default Vortex;