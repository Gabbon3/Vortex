class Buffer {
    static base64 = {
        /**
         * Converte una stringa base64 in un Uint8Array
         * @param {string} base64 
         * @returns {Uint8Array}
         */
        bytes_(base64) {
            let bin = atob(base64);
            let bytes = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) {
                bytes[i] = bin.charCodeAt(i);
            }
            return bytes;
        },
        /**
         * Converte un Uint8Array in una stringa base64
         * @param {Uint8Array} buffer 
         * @returns {string}
         */
        _bytes(buffer) {
            let bin = "";
            const bytes = new Uint8Array(buffer.buffer);
            for (let i = 0; i < bytes.byteLength; i++) {
                bin += String.fromCharCode(bytes[i]);
            }
            return window.btoa(bin);
        },
    };

    static txt = {
        /**
         * Converte una stringa di testo in un Uint8Array
         * @param {string} txt 
         * @returns {Uint8Array}
         */
        bytes_(txt) {
            return new TextEncoder().encode(txt);
        },
        /**
         * Converte un Uint8Array in una stringa di testo
         * @param {Uint8Array} buffer 
         * @returns {string}
         */
        _bytes(buffer) {
            return new TextDecoder().decode(buffer);
        },
        /**
         * Converte del testo in un Uint16Array
         * @param {String} txt 
         * @returns 
         */
        Uint16_(txt) {
            let B = typeof txt === 'string' ? this.bytes_(txt) : txt;
            const length = B.length;
            // -- aggiungi padding se necessario
            const padded_length = length + (length % 2);
            // ---
            const U16 = new Uint16Array(padded_length / 2);
            for (let i = 0; i < length; i += 2) {
                U16[i / 2] = (B[i] | (B[i + 1] << 8)) >>> 0;
            }
            // ---
            return U16;
        }
    };

    static bigint = {
        /**
         * Converte un Uint8Array in un BigInt
         * @param {Uint8Array} buffer 
         * @returns {BigInt}
         */
        _bytes(byte) {
            let n = 0n;
            const L = byte.length;
            // ---
            for (let i = 0; i < L; i++) {
                n = (n << 8n) | BigInt(byte[i]);
            }
            // ---
            return n;
        },
        /**
         * Converte un BigInt in un Uint8Array
         * @param {BigInt} n 
         * @returns {Uint8Array}
         */
        bytes_(n) {
            const L = Math.ceil(n.toString(2).length / 8);
            // ---
            const B = new Uint8Array(L);
            for (let i = 0; i < L; i++) {
                B[i] = Number(n & 255n);
                n >>= 8n;
            }
            // ---
            return B.reverse();
        }
    };

    static merge(buffers, size) {
        // -- ottengo la lunghezza totale
        let length = 0;
        for (const buffer of buffers) {
            length += buffer.length;
        }
        // -- unisci tutti gli array
        let merged_array;
        // ---
        switch (size) {
            case 8:
                merged_array = new Uint8Array(length);
                break;
            case 16:
                merged_array = new Uint16Array(length);
                break;
            case 32:
                merged_array = new Uint32Array(length);
                break;
            default:
                throw new Error("Invalid size");
        }
        // ---
        let offset = 0;
        for (const buffer of buffers) {
            merged_array.set(buffer, offset);
            offset += buffer.length;
        }
        // --
        return merged_array;
    }

    /**
     * Compara due Buffer verificando se sono uguali
     * @param {Array} a 
     * @param {Array} b 
     * @returns 
     */
    static compare(a, b) {
        if (a.length != b.length) throw new Error("Invalid size a is different than b");
        // ---
        const L = a.length;
        // ---
        for (let i = 0; i < L; i++) {
            if (a[i] !== b[i]) return false;
        }
        // ---
        return true;
    }
}

export default Buffer;