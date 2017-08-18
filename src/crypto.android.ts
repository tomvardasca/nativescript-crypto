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

const X509EncodedKeySpec = java.security.spec.X509EncodedKeySpec;
const PKCS8EncodedKeySpec = java.security.spec.PKCS8EncodedKeySpec;
const SecretKeySpec = javax.crypto.spec.SecretKeySpec;
const cGCMspec: any = javax.crypto.spec;
const GCMParameterSpec = cGCMspec.GCMParameterSpec;
const KeyFactory = java.security.KeyFactory;
const PrivateKey = java.security.PrivateKey;
const PublicKey = java.security.PublicKey;
const Security = java.security.Security;
const Signature = java.security.Signature;
const Cipher = javax.crypto.Cipher;

export class NSCrypto implements INSCryto {
  private crypto_pwhash_consts = {
    scryptsalsa208sha256: {
      mem_limits: {
        min: 8192 * 7168 * 2,
        max: 8192 * 9126 * 2
      },
      ops_limits: {
        min: 768 * 1024 * 2,
        max: 768 * 2048 * 2
      }
    },
    argon2i: {
      mem_limits: { min: 8192 * 308 * 2, max: 8192 * 436 * 2 },
      ops_limits: { min: 4, max: 6 }
    }
  };

  private _hashTypeLibsodiumNamespace = {
    sha256: 'crypto_hash_sha256',
    sha512: 'crypto_hash_sha512'
  };

  private rsaEncPaddingType = {
    pkcs1: 'RSA/NONE/PKCS1Padding',
    oaep: 'RSA/NONE/OAEPwithSHA-1andMGF1Padding'
  };

  private rsaSigDigestType = {
    sha1: 'SHA1withRSA',
    sha256: 'SHA256withRSA',
    sha512: 'SHA512withRSA'
  };

  hash(input: string, type: string): string {
    if (Object.keys(this._hashTypeLibsodiumNamespace).indexOf(type) === -1) {
      throw new Error(`hash type "${type}" not found!`);
    }
    input = Base64.decode(input, Base64.DEFAULT);
    Sodium.sodium_init();
    let hash_libsodium_namespace = this._hashTypeLibsodiumNamespace[type];
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
    alg = alg || 'argon2i';

    if (!mem_limits) {
      const diff =
        this.crypto_pwhash_consts[alg].mem_limits.max -
        this.crypto_pwhash_consts[alg].mem_limits.min;
      mem_limits =
        this.crypto_pwhash_consts[alg].mem_limits.min +
        Sodium.randombytes_uniform(diff + 1); // randombytes_uniform upper_bound is (excluded)
    }
    if (!ops_limits) {
      const diff =
        this.crypto_pwhash_consts[alg].ops_limits.max -
        this.crypto_pwhash_consts[alg].ops_limits.min;
      ops_limits =
        this.crypto_pwhash_consts[alg].ops_limits.min +
        Sodium.randombytes_uniform(diff + 1); // randombytes_uniform upper_bound is (excluded)
    }

    const derived_key = Array.create('byte', key_size);
    if (alg === 'scryptsalsa208sha256') {
      if (!salt) {
        _salt = Array.create(
          'byte',
          Sodium.crypto_pwhash_scryptsalsa208sha256_saltbytes()
        );
        Sodium.randombytes_buf(_salt, _salt.length);
      }
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
    } else if (alg === 'argon2i') {
      if (!salt) {
        _salt = Array.create('byte', Sodium.crypto_pwhash_saltbytes());
        Sodium.randombytes_buf(_salt, _salt.length);
      }
      if (
        Sodium.crypto_pwhash(
          derived_key,
          key_size,
          password,
          password.length,
          _salt,
          ops_limits,
          mem_limits,
          Sodium.crypto_pwhash_alg_argon2i13()
        ) !== 0
      ) {
        throw new Error('deriveSecureKey out of memory');
      }
    } else {
      throw new Error(`deriveSecureKey algorithm "${alg}" not found`);
    }
    return {
      key: Base64.encodeToString(derived_key, Base64.DEFAULT),
      salt: Base64.encodeToString(_salt, Base64.DEFAULT),
      ops_limits: ops_limits,
      mem_limits: mem_limits,
      alg: alg
    };
  }

  secureSymetricAEADkeyLength(): number {
    return Sodium.crypto_aead_chacha20poly1305_ietf_keybytes();
  }
  secureSymetricAEADnonceLength(): number {
    return Sodium.crypto_aead_chacha20poly1305_ietf_npubbytes();
  }

  encryptSecureSymetricAEAD(
    key: string,
    plainb: string,
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
    const plainb_bytes = Base64.decode(plainb, Base64.DEFAULT);
    const cipherb = Array.create(
      'byte',
      plainb_bytes.length + Sodium.crypto_aead_chacha20poly1305_ietf_abytes()
    );
    const clen_p = Array.create('int', 1);
    const aad_bytes = Base64.decode(aad, Base64.DEFAULT);
    const pnonce_bytes = Base64.decode(pnonce, Base64.DEFAULT);

    Sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
      cipherb,
      clen_p,
      plainb_bytes,
      plainb_bytes.length,
      aad_bytes,
      aad_bytes.length,
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
    const aad_bytes = new java.lang.String(aad).getBytes(
      StandardCharsets.UTF_8
    );
    const pnonce_bytes = Base64.decode(pnonce, Base64.DEFAULT);

    Sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
      plaint_bytes,
      mlen_p,
      cipherb_bytes,
      cipherb_bytes.length,
      aad_bytes,
      aad_bytes.length,
      pnonce_bytes,
      null,
      key_bytes
    );
    return Base64.encodeToString(plaint_bytes, Base64.DEFAULT);
  }

  private initSpongyCastle() {
    if (java.security.Security.getProvider('SC') == null) {
      java.security.Security.addProvider(
        new org.spongycastle.jce.provider.BouncyCastleProvider()
      );
    }
  }

  private hasServiceProvider(service: string, provider: string) {
    const _provider = java.security.Security.getProvider(provider);
    if (provider != null) {
      if (_provider.getService('Cipher', service) != null) return true;
    }
    return false;
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
    const key_bytes = Base64.decode(key, Base64.DEFAULT);
    const plaint_bytes = Base64.decode(plaint, Base64.DEFAULT);
    const aad_bytes = Base64.decode(aad, Base64.DEFAULT);
    const iv_bytes = Base64.decode(iv, Base64.DEFAULT);

    const keyC = new SecretKeySpec(key_bytes, 'AES');
    this.initSpongyCastle();
    const cipher: any = Cipher.getInstance('AES/GCM/NoPadding', 'SC');
    const spec = new GCMParameterSpec(tagLength, iv_bytes);
    cipher.init(Cipher.ENCRYPT_MODE, keyC, spec);
    cipher.updateAAD(aad_bytes);
    let cipherb = cipher.doFinal(plaint_bytes);

    // we will separate the authentication tag from the ciphertext array
    const tagb = Arrays.copyOfRange(
      cipherb,
      cipherb.length - tagLength / 8,
      cipherb.length
    );
    cipherb = Arrays.copyOfRange(cipherb, 0, cipherb.length - tagLength / 8);

    return {
      cipherb: Base64.encodeToString(cipherb, Base64.DEFAULT),
      atag: Base64.encodeToString(tagb, Base64.DEFAULT)
    };
    // const cipher = new NativeGCMCipher(new SystemNativeCryptoLibrary());

    // cipher.encryptInit(key_bytes, iv_bytes);
    // cipher.updateAad(aad_bytes, aad_bytes.length);

    // const buffer = Array.create('byte', cipher.getCipherBlockSize() + 256);
    // const content_length = plaint_bytes.length; // + aad_bytes.length + 1024;
    // const out_stream = new ByteArrayOutputStream(content_length);
    // const times = Math.floor(content_length / buffer.length);
    // const remainder = content_length % buffer.length;
    // let offset = 0;

    // for (let i = 0; i < times; ++i) {
    //   const written = cipher.update(
    //     plaint_bytes,
    //     offset,
    //     buffer.length,
    //     buffer,
    //     0
    //   );
    //   out_stream.write(buffer, 0, written);
    //   offset += buffer.length;
    // }
    // if (remainder > 0) {
    //   const written = cipher.update(plaint_bytes, offset, remainder, buffer, 0);
    //   out_stream.write(buffer, 0, written);
    // }

    // const tag = Array.create('byte', tagLength / 8);
    // cipher.encryptFinal(tag, tag.length);

    // return {
    //   cipherb: Base64.encodeToString(out_stream.toByteArray(), Base64.DEFAULT),
    //   atag: Base64.encodeToString(tag, Base64.DEFAULT)
    // };
  }
  decryptAES256GCM(
    key: string,
    cipherb: string,
    aad: string,
    iv: string,
    atag: string
  ): string {
    const key_bytes = Base64.decode(key, Base64.DEFAULT);
    const cipherb_bytes = Base64.decode(cipherb, Base64.DEFAULT);
    const aad_bytes = Base64.decode(aad, Base64.DEFAULT);
    const iv_bytes = Base64.decode(iv, Base64.DEFAULT);
    const atag_bytes = Base64.decode(atag, Base64.DEFAULT);

    const plainb_bytes = Array.create('byte', cipherb_bytes.length);

    const keyC = new SecretKeySpec(key_bytes, 'AES');
    this.initSpongyCastle();
    const cipher: any = Cipher.getInstance('AES/GCM/NoPadding', 'SC');
    const spec = new GCMParameterSpec(atag_bytes.length * 8, iv_bytes);
    cipher.init(Cipher.DECRYPT_MODE, keyC, spec);
    cipher.updateAAD(aad_bytes);

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

    let plaint_bytes = cipher.doFinal(cipherb_bytes_complete);

    // const cipher = new NativeGCMCipher(new SystemNativeCryptoLibrary());

    // cipher.decryptInit(key_bytes, iv_bytes);
    // cipher.updateAad(aad_bytes, aad_bytes.length);

    // const buffer = Array.create('byte', cipher.getCipherBlockSize() + 256);
    // const content_length = cipherb_bytes.length; // +   aad_bytes.length + 1024;
    // const out_stream = new ByteArrayOutputStream(content_length);
    // const times = Math.floor(content_length / buffer.length);
    // const remainder = content_length % buffer.length;
    // let offset = 0;
    // for (let i = 0; i < times; ++i) {
    //   const written = cipher.update(
    //     cipherb_bytes,
    //     offset,
    //     buffer.length,
    //     buffer,
    //     0
    //   );
    //   out_stream.write(buffer, 0, written);
    //   offset += buffer.length;
    // }
    // if (remainder > 0) {
    //   const written = cipher.update(
    //     cipherb_bytes,
    //     offset,
    //     remainder,
    //     buffer,
    //     0
    //   );
    //   out_stream.write(buffer, 0, written);
    // }

    // cipher.decryptFinal(atag_bytes, atag_bytes.length);
    // return Base64.encodeToString(out_stream.toByteArray(), Base64.DEFAULT);
    return Base64.encodeToString(plaint_bytes, Base64.DEFAULT);
  }

  encryptRSA(pub_key_pem: string, plainb: string, padding: string): string {
    pub_key_pem = pub_key_pem.replace('-----BEGIN PUBLIC KEY-----\n', '');
    pub_key_pem = pub_key_pem.replace('-----END PUBLIC KEY-----', '');
    let publicKeyBytes = Base64.decode(pub_key_pem, Base64.DEFAULT);
    let keySpec = new X509EncodedKeySpec(publicKeyBytes);
    let keyFactory = KeyFactory.getInstance('RSA');
    let pubKey = keyFactory.generatePublic(keySpec);
    let cipher = Cipher.getInstance(this.rsaEncPaddingType[padding]); // or try with "RSA"
    cipher.init(Cipher.ENCRYPT_MODE, pubKey);
    let encrypted = cipher.doFinal(Base64.decode(plainb, Base64.DEFAULT));
    return Base64.encodeToString(encrypted, Base64.DEFAULT);
  }
  decryptRSA(priv_key_pem: string, cipherb: string, padding: string): string {
    priv_key_pem = priv_key_pem.replace(
      '-----BEGIN RSA PRIVATE KEY-----\n',
      ''
    );
    priv_key_pem = priv_key_pem.replace('-----END RSA PRIVATE KEY-----', '');
    let privateKeyBytes = Base64.decode(priv_key_pem, Base64.DEFAULT);
    let keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
    let keyFactory = KeyFactory.getInstance('RSA');
    let privKey = keyFactory.generatePrivate(keySpec);
    let cipher = Cipher.getInstance(this.rsaEncPaddingType[padding]); // or try with "RSA"
    cipher.init(Cipher.DECRYPT_MODE, privKey);
    let paintb = cipher.doFinal(Base64.decode(cipherb, Base64.DEFAULT));
    return Base64.encodeToString(paintb, Base64.DEFAULT);
  }
  signRSA(priv_key_pem: string, messageb: string, digest_type: string): string {
    priv_key_pem = priv_key_pem.replace(
      '-----BEGIN RSA PRIVATE KEY-----\n',
      ''
    );
    priv_key_pem = priv_key_pem.replace('-----END RSA PRIVATE KEY-----', '');
    let privateKeyBytes = Base64.decode(priv_key_pem, Base64.DEFAULT);
    let keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
    let keyFactory = KeyFactory.getInstance('RSA');
    let privKey = keyFactory.generatePrivate(keySpec);
    let signature = Signature.getInstance(this.rsaSigDigestType[digest_type]);
    signature.initSign(privKey);
    signature.update(Base64.decode(messageb, Base64.DEFAULT));
    let signatureBytes = signature.sign();
    return Base64.encodeToString(signatureBytes, Base64.DEFAULT);
  }
  verifyRSA(
    pub_key_pem: string,
    messageb: string,
    signatureb: string,
    digest_type: string
  ): boolean {
    pub_key_pem = pub_key_pem.replace('-----BEGIN PUBLIC KEY-----\n', '');
    pub_key_pem = pub_key_pem.replace('-----END PUBLIC KEY-----', '');
    let publicKeyBytes = Base64.decode(pub_key_pem, Base64.DEFAULT);
    let keySpec = new X509EncodedKeySpec(publicKeyBytes);
    let keyFactory = KeyFactory.getInstance('RSA');
    let pubKey = keyFactory.generatePublic(keySpec);
    let signature = Signature.getInstance(this.rsaSigDigestType[digest_type]);
    signature.initVerify(pubKey);
    signature.update(Base64.decode(messageb, Base64.DEFAULT));
    return signature.verify(Base64.decode(signatureb, Base64.DEFAULT));
  }

  deflate(input: string): string {
    let data = Base64.decode(input, Base64.DEFAULT);
    let output = Array.create('byte', data.length);
    let compresser = new java.util.zip.Deflater();
    compresser.setInput(data, 0, data.length);
    compresser.finish();
    let compressedDataLength = compresser.deflate(output);
    compresser.end();
    output = Arrays.copyOf(output, compressedDataLength);
    return Base64.encodeToString(output, Base64.DEFAULT);
  }
  inflate(input: string): string {
    let data = Base64.decode(input, Base64.DEFAULT);
    let decompresser = new java.util.zip.Inflater();
    decompresser.setInput(data, 0, data.length);
    let output = Array.create('byte', data.length * 20);
    let decompressedDataLength = decompresser.inflate(output);
    decompresser.end();
    output = Arrays.copyOf(output, decompressedDataLength);
    return Base64.encodeToString(output, Base64.DEFAULT);
  }

  base64encode(input: string): string {
    input = new java.lang.String(input).getBytes(StandardCharsets.UTF_8);
    return Base64.encodeToString(input, Base64.DEFAULT);
  }

  base64decode(input: string): string {
    let data = Base64.decode(input, Base64.DEFAULT);
    return new java.lang.String(data, StandardCharsets.UTF_8);
  }

  randomUUID(): string {
    return java.util.UUID.randomUUID().toString();
  }

  keyWrapAES(wrappingKey: string, key: string): string {
    const wrappingKeyData = Base64.decode(wrappingKey, Base64.DEFAULT);
    const keyData = Base64.decode(key, Base64.DEFAULT);
    let cipher;
    if (this.hasServiceProvider('AESWrap', 'BC')) {
      cipher = Cipher.getInstance('AESWrap', 'BC');
    } else {
      this.initSpongyCastle();
      cipher = Cipher.getInstance('AESWrap', 'SC');
    }
    cipher.init(Cipher.WRAP_MODE, new SecretKeySpec(wrappingKeyData, 'AES'));
    return Base64.encodeToString(
      cipher.wrap(new SecretKeySpec(keyData, 'AES')),
      Base64.DEFAULT
    );
  }
  keyUnWrapAES(unwrappingKey: string, wrappedkey: string): string {
    const unwrappingKeyData = Base64.decode(unwrappingKey, Base64.DEFAULT);
    const wrappedkeyData = Base64.decode(wrappedkey, Base64.DEFAULT);
    let cipher;
    if (this.hasServiceProvider('AESWrap', 'BC')) {
      cipher = Cipher.getInstance('AESWrap', 'BC');
    } else {
      this.initSpongyCastle();
      cipher = Cipher.getInstance('AESWrap', 'SC');
    }
    cipher.init(
      Cipher.UNWRAP_MODE,
      new SecretKeySpec(unwrappingKeyData, 'AES')
    );
    return Base64.encodeToString(
      cipher.unwrap(wrappedkeyData, 'AES', Cipher.SECRET_KEY).getEncoded(),
      Base64.DEFAULT
    );
  }
}
