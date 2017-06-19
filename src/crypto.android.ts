import { INSCryto } from './crypto.common';
declare var android: any;
declare var java: any;
declare var org: any;

const NaCl = org.libsodium.jni.NaCl;
const Sodium_ = NaCl.sodium();
const Sodium = org.libsodium.jni.Sodium;

const Base64 = android.util.Base64;
const StandardCharsets = java.nio.charset.StandardCharsets;

const _hashTypeLibsodiumNamespace = {
  sha256: 'crypto_hash_sha256',
  sha512: 'crypto_hash_sha512'
};

const crypto_pwhash_consts = {
  scryptsalsa208sha256: {
    mem_limits: {
      min: 8192 * 7168 * 4,
      max: 8192 * 9126 * 4
    },
    ops_limits: {
      min: 768 * 1024 * 6,
      max: 768 * 2048 * 6
    }
  }
};

export class NSCrypto implements INSCryto {
  hash(input: string, type: string): string {
    if (Object.keys(_hashTypeLibsodiumNamespace).indexOf(type) === -1) {
      throw new Error(`hash type "${type}" not found!`);
    }
    input = new java.lang.String(input).getBytes(StandardCharsets.UTF_8);
    Sodium.sodium_init();
    let hash_libsodium_namespace = _hashTypeLibsodiumNamespace[type];
    let hash = Array.create(
      'byte',
      Sodium[hash_libsodium_namespace + '_bytes']()
    );
    Sodium[hash_libsodium_namespace](hash, input, input.length);
    return Base64.encodeToString(hash, Base64.DEFAULT);
  }

  secureRandomBytes(length: number): string {
    Sodium.sodium_init();
    let bytes = Array.create('byte', length);
    Sodium.randombytes_buf(bytes, length);
    return Base64.encodeToString(bytes, Base64.DEFAULT);
  }

  deriveSecureKey(
    password: string,
    key_size: number,
    salt?: string,
    ops_limits?: number,
    mem_limits?: number,
    alg?: string
  ): {
    key: string;
    salt: string;
    ops_limits: number;
    mem_limits: number;
    alg: string;
  } {
    Sodium.sodium_init();
    password = new java.lang.String(password).getBytes(StandardCharsets.UTF_8);
    let _salt;
    if (salt) {
      _salt = Base64.decode(salt, Base64.DEFAULT);
    }
    alg = alg || 'scryptsalsa208sha256';
    if (!mem_limits) {
      let diff =
        crypto_pwhash_consts[alg].mem_limits.max -
        crypto_pwhash_consts[alg].mem_limits.min;
      mem_limits =
        crypto_pwhash_consts[alg].mem_limits.min +
        Sodium.randombytes_uniform(diff + 1); // randombytes_uniform upper_bound is (excluded)
    }
    if (!ops_limits) {
      let diff =
        crypto_pwhash_consts[alg].ops_limits.max -
        crypto_pwhash_consts[alg].ops_limits.min;
      ops_limits =
        crypto_pwhash_consts[alg].ops_limits.min +
        Sodium.randombytes_uniform(diff + 1); // randombytes_uniform upper_bound is (excluded)
    }

    if (alg === 'scryptsalsa208sha256') {
      if (!salt) {
        _salt = Array.create(
          'byte',
          Sodium.crypto_pwhash_scryptsalsa208sha256_saltbytes()
        );
        Sodium.randombytes_buf(_salt, _salt.length);
      }
      let derived_key = Array.create('byte', key_size);
      if (
        Sodium.crypto_pwhash_scryptsalsa208sha256(
          derived_key,
          key_size,
          password,
          password.length,
          _salt,
          ops_limits,
          mem_limits
        ) !== 0
      ) {
        throw new Error('deriveSecureKey out of memory');
      }
      return {
        key: Base64.encodeToString(derived_key, Base64.DEFAULT),
        salt: Base64.encodeToString(_salt, Base64.DEFAULT),
        ops_limits: ops_limits,
        mem_limits: mem_limits,
        alg: alg
      };
    } else {
      throw new Error(`deriveSecureKey algorithm "${alg}" not found`);
    }
  }

  secureSymetricAEADkeyLength(): number {
    throw new Error('Method not implemented.');
  }
  secureSymetricAEADnonceLength(): number {
    throw new Error('Method not implemented.');
  }

  encryptSecureSymetricAEAD(
    key: string,
    plaint: string,
    aad: string,
    pnonce: string,
    alg?: string
  ): {
    ciphert: string;
    alg: string;
  } {
    throw new Error('Method not implemented.');
  }
  decryptSecureSymetricAEAD(
    key: string,
    ciphert: string,
    aad: string,
    pnonce: string,
    alg?: string
  ): string {
    throw new Error('Method not implemented.');
  }

  encryptAES256GCM(
    key: string,
    plaint: string,
    aad: string,
    iv: string,
    tagLength?: number
  ): {
    cipherb: string;
    atag: string;
  } {
    throw new Error('Method not implemented.');
  }
  decryptAES256GCM(
    key: string,
    cipherb: string,
    aad: string,
    iv: string,
    atag: string
  ): string {
    throw new Error('Method not implemented.');
  }

  encryptRSA(pub_key_pem: string, plainb: string, padding: string): string {
    throw new Error('Method not implemented.');
  }
  decryptRSA(priv_key_pem: string, cipherb: string, padding: string): string {
    throw new Error('Method not implemented.');
  }
  signRSA(priv_key_pem: string, messageb: string, digest_type: string): string {
    throw new Error('Method not implemented.');
  }
  verifyRSA(
    pub_key_pem: string,
    messageb: string,
    signatureb: string,
    digest_type: string
  ): boolean {
    throw new Error('Method not implemented.');
  }

  deflate(input: string, alg?: string): string {
    let data = new java.lang.String(input).getBytes(StandardCharsets.UTF_8);
    let output = Array.create('byte', data.length);
    let compresser = new java.util.zip.Deflater();
    compresser.setInput(input);
    compresser.finish();
    let compressedDataLength = compresser.deflate(output);
    compresser.end();
    output = java.util.Arrays.copyOf(output, compressedDataLength);
    return Base64.encodeToString(output, Base64.DEFAULT);
  }
  inflate(input: string, alg?: string): string {
    let data = Base64.decode(input, Base64.DEFAULT);
    let decompresser = new java.util.zip.Inflater();
    decompresser.setInput(data, 0, data.length);
    let output = Array.create('byte', data.length * 20);
    let decompressedDataLength = decompresser.inflate(output);
    decompresser.end();
    output = java.util.Arrays.copyOf(output, decompressedDataLength);
    return new java.lang.String(output, StandardCharsets.UTF_8);
  }

  base64encode(input: string): string {
    input = new java.lang.String(input).getBytes(StandardCharsets.UTF_8);
    return Base64.encodeToString(input, Base64.DEFAULT);
  }

  base64decode(input: string): string {
    let data = Base64.decode(input, Base64.DEFAULT);
    return new java.lang.String(data, StandardCharsets.UTF_8);
  }
}
