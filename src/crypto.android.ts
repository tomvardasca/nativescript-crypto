import { INSCryto } from './crypto.common';
declare var android: any;
declare var java: any;
declare var org: any;
declare var com: any;

const NaCl = org.libsodium.jni.NaCl;
const Sodium_ = NaCl.sodium();
const Sodium = org.libsodium.jni.Sodium;

const Base64 = android.util.Base64;
const StandardCharsets = java.nio.charset.StandardCharsets;
const ByteArrayOutputStream = java.io.ByteArrayOutputStream;
const ByteArrayInputStream = java.io.ByteArrayInputStream;
const Arrays = java.util.Arrays;
const System = java.lang.System;

const DEFAULT_ENCRYPT_BUFFER_SIZE = 256;
const SystemNativeCryptoLibrary =
  com.facebook.crypto.util.SystemNativeCryptoLibrary;
const NativeGCMCipher = com.facebook.crypto.cipher.NativeGCMCipher;
const NativeGCMCipherOutputStream =
  com.facebook.crypto.streams.NativeGCMCipherOutputStream;
const NativeGCMCipherInputStream =
  com.facebook.crypto.streams.NativeGCMCipherInputStream;
const FixedSizeByteArrayOutputStream =
  com.facebook.crypto.streams.FixedSizeByteArrayOutputStream;

const _hashTypeLibsodiumNamespace = {
  sha256: 'crypto_hash_sha256',
  sha512: 'crypto_hash_sha512'
};

const crypto_pwhash_consts = {
  scryptsalsa208sha256: {
    mem_limits: {
      min: 8192 * 7168 * 2,
      max: 8192 * 9126 * 2
    },
    ops_limits: {
      min: 768 * 1024 * 2,
      max: 768 * 2048 * 2
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
      const diff =
        crypto_pwhash_consts[alg].mem_limits.max -
        crypto_pwhash_consts[alg].mem_limits.min;
      mem_limits =
        crypto_pwhash_consts[alg].mem_limits.min +
        Sodium.randombytes_uniform(diff + 1); // randombytes_uniform upper_bound is (excluded)
    }
    if (!ops_limits) {
      const diff =
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
    return Sodium.crypto_aead_chacha20poly1305_ietf_keybytes();
  }
  secureSymetricAEADnonceLength(): number {
    return Sodium.crypto_aead_chacha20poly1305_ietf_npubbytes();
  }

  encryptSecureSymetricAEAD(
    key: string,
    plaint: string,
    aad: string,
    pnonce: string,
    alg?: string
  ): {
    cipherb: string;
    alg: string;
  } {
    if (alg && alg !== 'chacha20poly1305_ietf') {
      throw new Error(
        `decryptSecureSymetricAEAD algorith ${alg} not found or is not available in this hardware`
      );
    }

    const key_bytes = Base64.decode(key, Base64.DEFAULT);
    const plaint_bytes = new java.lang.String(plaint).getBytes(
      StandardCharsets.UTF_8
    );
    const cipherb = Array.create(
      'byte',
      plaint_bytes.length + Sodium.crypto_aead_chacha20poly1305_ietf_abytes()
    );
    const clen_p = Array.create('int', 1);
    const ad_bytes = new java.lang.String(aad).getBytes(StandardCharsets.UTF_8);
    const pnonce_bytes = Base64.decode(pnonce, Base64.DEFAULT);

    Sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
      cipherb,
      clen_p,
      plaint_bytes,
      plaint_bytes.length,
      ad_bytes,
      ad_bytes.length,
      pnonce_bytes,
      null,
      key_bytes
    );
    return {
      cipherb: Base64.encodeToString(cipherb, Base64.DEFAULT),
      alg: 'chacha20poly1305_ietf'
    };
  }
  decryptSecureSymetricAEAD(
    key: string,
    cipherb: string,
    aad: string,
    pnonce: string,
    alg?: string
  ): string {
    if (alg && alg !== 'chacha20poly1305_ietf') {
      throw new Error(
        `decryptSecureSymetricAEAD algorith ${alg} not found or is not available in this hardware`
      );
    }
    const key_bytes = Base64.decode(key, Base64.DEFAULT);
    const cipherb_bytes = Base64.decode(cipherb, Base64.DEFAULT);

    const plaint_bytes = Array.create(
      'byte',
      cipherb_bytes.length - Sodium.crypto_aead_chacha20poly1305_ietf_abytes()
    );
    const mlen_p = Array.create('int', 1);
    const ad_bytes = new java.lang.String(aad).getBytes(StandardCharsets.UTF_8);
    const pnonce_bytes = Base64.decode(pnonce, Base64.DEFAULT);

    Sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
      plaint_bytes,
      mlen_p,
      cipherb_bytes,
      cipherb_bytes.length,
      ad_bytes,
      ad_bytes.length,
      pnonce_bytes,
      null,
      key_bytes
    );
    return new java.lang.String(plaint_bytes, StandardCharsets.UTF_8);
  }

  encryptAES256GCM(
    key: string,
    plaint: string,
    aad: string,
    iv: string,
    tagLength: number = 128
  ): {
    cipherb: string;
    atag: string;
  } {
    const cipher = new NativeGCMCipher(new SystemNativeCryptoLibrary());

    const key_bytes = Base64.decode(key, Base64.DEFAULT);
    const plaint_bytes = new java.lang.String(plaint).getBytes(
      StandardCharsets.UTF_8
    );
    const aad_bytes = new java.lang.String(aad).getBytes(
      StandardCharsets.UTF_8
    );
    const iv_bytes = Base64.decode(key, Base64.DEFAULT);

    cipher.encryptInit(key_bytes, iv_bytes);
    cipher.updateAad(aad_bytes, aad_bytes.length);

    const enc_stream = new FixedSizeByteArrayOutputStream(
      plaint_bytes.length + tagLength
    );
    const cipher_stream = new NativeGCMCipherOutputStream(
      enc_stream,
      cipher,
      null,
      tagLength
    );
    cipher_stream.write(plaint_bytes);
    cipher_stream.close();
    let cipherb = enc_stream.getBytes();
    // we will separate the authentication tag from the ciphertext array
    const tagb = Arrays.copyOfRange(
      cipherb,
      cipherb.length - tagLength - 1,
      cipherb.length
    );
    cipherb = Arrays.copyOfRange(cipherb, 0, cipherb.length - tagLength);

    return {
      cipherb: Base64.encodeToString(cipherb, Base64.DEFAULT),
      atag: Base64.encodeToString(tagb, Base64.DEFAULT)
    };
  }
  decryptAES256GCM(
    key: string,
    cipherb: string,
    aad: string,
    iv: string,
    atag: string
  ): string {
    const cipher = new NativeGCMCipher(new SystemNativeCryptoLibrary());

    const key_bytes = Base64.decode(key, Base64.DEFAULT);
    const cipherb_bytes = Base64.decode(cipherb, Base64.DEFAULT);
    const iv_bytes = Base64.decode(key, Base64.DEFAULT);
    const atag_bytes = Base64.decode(atag, Base64.DEFAULT);

    const aad_bytes = new java.lang.String(aad).getBytes(
      StandardCharsets.UTF_8
    );

    const cleart_bytes = Array.create('byte', cipherb_bytes.length);

    cipher.decryptInit(key_bytes, iv_bytes);
    cipher.updateAad(aad_bytes, aad_bytes.length);

    // we will concat the authentication tag to the ciphertext array
    const cipherb_bytes_complete = Array.create(
      'byte',
      cipherb_bytes.length + atag_bytes.length
    );
    System.arraycopy(
      cipherb_bytes,
      0,
      cipherb_bytes_complete,
      0,
      cipherb_bytes.length
    );
    System.arraycopy(
      atag_bytes,
      0,
      cipherb_bytes_complete,
      cipherb_bytes.length,
      atag_bytes.length
    );

    const dec_stream = new ByteArrayInputStream(cipherb_bytes_complete);
    const cipher_stream = new NativeGCMCipherInputStream(
      dec_stream,
      atag_bytes.length
    );
    cipher_stream.read(cleart_bytes);
    cipher_stream.close();
    return new java.lang.String(cleart_bytes, StandardCharsets.UTF_8);
  }

  encryptRSA(pub_key_pem: string, plainb: string, padding: string): string {
    /*
		        byte[] publicBytes = Base64.decode(PUBLIC_KEY, Base64.DEFAULT);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pubKey = keyFactory.generatePublic(keySpec);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING"); //or try with "RSA"
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        encrypted = cipher.doFinal(txt.getBytes());
        encoded = Base64.encodeToString(encrypted, Base64.DEFAULT); */
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
    output = Arrays.copyOf(output, compressedDataLength);
    return Base64.encodeToString(output, Base64.DEFAULT);
  }
  inflate(input: string, alg?: string): string {
    let data = Base64.decode(input, Base64.DEFAULT);
    let decompresser = new java.util.zip.Inflater();
    decompresser.setInput(data, 0, data.length);
    let output = Array.create('byte', data.length * 20);
    let decompressedDataLength = decompresser.inflate(output);
    decompresser.end();
    output = Arrays.copyOf(output, decompressedDataLength);
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
