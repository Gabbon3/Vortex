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
     * Operazioni sul counter
     */
    static counter = {
        /**
         * Restituisce il contatore basandosi sullo XOR consecutivo eseguito su tutte le parole di un Uint32Array
         * @param {Uint32Array} KN sta per K chiave N nonche, in base a quello che viene passato viene eseguito lo xor di tutte le parole che lo compongono
         * @returns {Int32Array}
        */
        xor(KN) {
            // -- numero di parole
            const L = KN.length;
            // -- contatore da restituire
            const C = new Uint32Array([KN[0]]);
            for (let i = 1; i < L; i++) {
                C[0] ^= KN[i];
            }
            // ---
            return C;
        },
        /**
         * Ottieni il contatore
         * @param {Uint32Array} K chiave
         * @param {Uint32Array} N nonche
         */
        generate(K, N) {
            const CK = this.xor(K);
            const CN = this.xor(N);
            return new Uint32Array([CK[0], CN[0]]);
        }
    };
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
     * @returns {ArrayBuffer}
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
            // -- btc = word (32 bit) to copy
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
     * @param {String} M testo
     * @param {String} K chiave base 64
     * @param {String} N nonce base 64
     */
    static encrypt(M, K, N = null) {
        // -- converto in Array tipizzati
        M = super.txt.bytes_(M);
        const K8 = super.base64.bytes_(K); // chiave in byte
        // ---
        K = new Uint32Array(K8.buffer);
        N = new Uint32Array(N === null ? this.random_bytes(this.nonche_size).buffer : super.base64.bytes_(N).buffer);
        // ---
        const L = M.length;
        // -- contatore
        const C = this.counter.generate(K, N);
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
            EM: super.base64._bytes(EM),
            N: super.base64._bytes(N)
        };
    }
    /**
     * Decifra utilizzando Vortex
     * @param {String} EMT testo cifrato + tag autenticazione in base64
     * @param {String} K chiave base 64
     * @param {String} N nonce base 64
     */
    static decrypt(EMT, K, N) {
        // ---
        EMT = super.base64.bytes_(EMT);
        // -- estraggo il tag dal messaggio
        const T = EMT.subarray(EMT.length - 16); // tag autenticazione
        const EM = EMT.subarray(0, EMT.length - 16);
        // ---
        const K8 = super.base64.bytes_(K); // chiave in byte
        K = new Uint32Array(K8.buffer);
        N = new Uint32Array(super.base64.bytes_(N).buffer);
        // ---
        const L = EM.length;
        // -- contatore
        const C = this.counter.generate(K, N);
        // ---
        const KS = this.keystream(K, N, C, L);
        // ---
        let M = new Uint8Array(L);
        for (let i = 0; i < L; i++) {
            M[i] = EM[i] ^ KS[i];
        }
        M = super.txt._bytes(M);
        // -- KP = Chiave Poly
        const KP = this.poly_key(K, N, C);
        // -- verifico il tag
        const TD = this.poly_1305(M, KP); // Tag generato dal testo appena Decifrato
        if (Buffer.compare(TD, T) === false) return null;
        // ---
        return M;
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
     * @param {String, Uint8Array} M messaggio
     * @param {Uint8Array} K chiave
     */
    static poly_1305(M, K) {
        M = new Uint16Array(typeof M === "string" ? Buffer.txt.bytes_(M).buffer : M.buffer);
        const L = M.length;
        // ---
        const r = K.subarray(0, 16);
        const R = super.bigint._bytes(r);
        const s = K.subarray(16);
        const S = super.bigint._bytes(s);
        // ---
        let acc = 0n;
        // ---
        for (let i = 0; i < L; i++) {
            const n = BigInt(M[i]);
            acc = (acc + n) * R % this.Mod;
        }
        // ---
        acc += S;
        acc %= this.Mod;
        // -- applico la maschera per ottenere 128 bit
        acc &= this.Mask;
        // ---
        return super.bigint.bytes_(acc);
    }
}

export default Vortex;