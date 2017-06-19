export interface INSCryto {
    hash(input: string, type: string): string;
    secureRandomBytes(length: number): any;
    deriveSecureKey(password: string, key_size: number, salt?: string, ops_limits?: number, mem_limits?: number, alg?: string): {
        key: string;
        salt: string;
        ops_limits: number;
        mem_limits: number;
        alg: string;
    };
    encryptSecureSymetricAEAD(key: string, plaint: string, aad: string, pnonce: string): string;
    decryptSecureSymetricAEAD(key: string, aad: string, pnonce: string): string;
    encryptAES256GCM(key: string, plaint: string, aad: string, iv: string): {
        ciphert: string;
        tag: string;
    };
    decryptAES256GCM(priv_key: string, ciphert: string, aad: string, iv: string): string;
    encryptRSA(pub_key_pem: string, plaint: string): string;
    decryptRSA(priv_key_pem: string, ciphert: string): string;
    signRSA(priv_key_pem: string, ciphert: string): string;
    verifyRSA(pub_key_pem: string, plaint: string): string;
    deflate(input: string, alg?: string): string;
    inflate(input: string, alg?: string): string;
    base64encode(input: string): string;
    base64decode(input: string): string;
}
