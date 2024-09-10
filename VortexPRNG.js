export default class VPNRG {
    /**
     * Numeri primi usati come costanti per generare byte casuali
     */
    static P = new Uint32Array([3631658089, 2367245317, 3358795523, 4133671973]);
    /**
     * Restituisce un seed derivandolo da un input dato
     * @param {String, ArrayBuffer} input
     * @returns {ArrayBuffer}
     */
    static async seed(input) {
        input = typeof input === "string" ? new TextEncoder().encode(input) : new Uint8Array(input);
        // ---
        const S = await crypto.subtle.digest("SHA-256", input);
        return new Uint32Array(S);
    }
    /**
     * Genera una sequenza di byte pseudo casuale
     * @param {Uint32Array} S seed
     * @param {int} L numero di byte in uscita
     */
    static prng(S, L) {
        // -- NW = Number of Words = numero di parole da ottenere
        const NW = Math.ceil(L / 4);
        // numero di byte generati
        let GL = 0;
        // -- inizializzo il risultato
        const R = new Uint32Array(NW);
        // -- calcolo il counter
        const C = this.counter(S);
        // -- iteratore usato per il counter
        let c = 0;
        const B = new Uint32Array(16);
        // ---
        while (GL < NW) {
            B.set(this.P); // --+ costante numeri primi
            B.set(S, 4); // --+ seed
            B.set(C, 12); // --+ contatore
            // ---
            this.stream(B);
            // -- wtc = word (32 bit) to copy
            const wtc = Math.min(B.length, NW - GL);
            // -- memorizzo nel risultato lo stream necessario
            R.set(B.subarray(0, wtc), GL);
            // -- aggiorno il numero di parole generate
            GL += 16;
            // -- aumento il contatore[c]
            C[c]++;
            // -- aggiorno la variabile c ottenendo la posizione del prossimo contatore da aumentare
            c = (c + 1) % 4;
        }
        // -- restituisco il numero di byte richiesto
        return new Uint8Array(R.buffer, 0, L);
    }

    /**
     * Genera il counter composto da 4 parole (128 bit)
     * @param {Uint32Array} S seed
     * @returns {Uint32Array} il counter composto
     */
    static counter(S) {
        const C = new Uint32Array(4);
        // -- inizializza
        C[0] = S[0] ^ this.P[0] + S[1];
        C[1] = S[2] - this.P[1] ^ S[3];
        C[2] = S[4] ^ this.P[2] + S[5];
        C[3] = S[6] - this.P[3] ^ S[7];
        // ---
        for (let i = 0; i < 16; i++) {
            this.mix(C, 2, 3, 0, 1);
            this.mix(C, 0, 1, 2, 3);
            this.mix(C, 3, 2, 1, 0);
            this.mix(C, 1, 0, 3, 2);
        }
        // ---
        return C;
    }
    /**
     * Genera lo stream mescolando i bit
     * @param {Uint32Array} B 16 elementi
     */
    static stream(B) {
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
     * Mescola i dati utilizzando calcoli bitwise semplici
     * @param {Uint16Array} B blocco di dati
     * @param {int} a 
     * @param {int} b 
     * @param {int} c 
     * @param {int} d 
     * @param {int} s shift
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
     * Calcola l'entropia sui byte
     * @param {Uint8Array} bytes 
     * @returns 
     */
    static entropy(bytes) {
        const BC = new Array(256).fill(0); // BC = bte count
        let L = 0;
        // ---
        for (let byte of bytes) {
            BC[byte]++;
            L++;
        }
        // ---
        let E = 0; // Entropia
        for (let C of BC) {
            if (C > 0) {
                const P = C / L; // Probabilità
                E -= P * Math.log2(P);
            }
        }
        // ---
        return E;
    }
    /**
     * Converte i byte in numeri
     * @param {Uint8Array} bytes 
     * @returns 
     */
    static to_number(bytes) {
        let N = 0;
        const L = bytes.length;
        if (L >= 7) throw new Error("Numero troppo grande");
        for (let i = 0; i < L; i++) {
            N = (N << 8) | bytes[i];
        }
        return N;
    }
}