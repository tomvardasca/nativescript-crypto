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
const KeyFactory = java.security.KeyFactory;
const PrivateKey = java.security.PrivateKey;
const PublicKey = java.security.PublicKey;
const Security = java.security.Security;
const Signature = java.security.Signature;
const Cipher = javax.crypto.Cipher;

const BlockCipher = org.spongycastle.crypto.BlockCipher;
const KeyParameter = org.spongycastle.crypto.params.KeyParameter;
const AESEngine = org.spongycastle.crypto.engines.AESFastEngine;
const KeyWrapEngine = org.spongycastle.crypto.engines.RFC3394WrapEngine; //KeyWrap
const RSAEngine = org.spongycastle.crypto.engines.RSAEngine;
const AEADParameters = org.spongycastle.crypto.params.AEADParameters;
const GCMBlockCipher = org.spongycastle.crypto.modes.GCMBlockCipher;
const RSAKeyParameters = org.spongycastle.crypto.params.RSAKeyParameters;
const RSAPrivateCrtKeyParameters =
  org.spongycastle.crypto.params.RSAPrivateCrtKeyParameters;
const OAEPEncoding = org.spongycastle.crypto.encodings.OAEPEncoding;
const PKCS1Encoding = org.spongycastle.crypto.encodings.PKCS1Encoding;
const PublicKeyFactory = org.spongycastle.crypto.util.PublicKeyFactory;
const PrivateKeyFactory = org.spongycastle.crypto.util.PrivateKeyFactory;
const SHA1Digest = org.spongycastle.crypto.digests.SHA1Digest;
const SHA256Digest = org.spongycastle.crypto.digests.SHA256Digest;
const SHA512Digest = org.spongycastle.crypto.digests.SHA512Digest;
const RSADigestSigner = org.spongycastle.crypto.signers.RSADigestSigner;

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
      mem_limits: { min: 8192 * 308, max: 8192 * 436 },
      ops_limits: { min: 4, max: 6 }
    }
  };

  private _hashTypeLibsodiumNamespace = {
    sha256: 'crypto_hash_sha256',
    sha512: 'crypto_hash_sha512'
  };

  private rsaEncPaddingEncodingType = {
    pkcs1: PKCS1Encoding,
    oaep: OAEPEncoding
  };

  private rsaSigDigestType = {
    sha1: SHA1Digest,
    sha256: SHA256Digest,
    sha512: SHA512Digest
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
    return Base64.encodeToString(hash, Base64.DEFAULT).trim();
  }

  secureRandomBytes(length: number): string {
    Sodium.sodium_init();
    let bytes = Array.create('byte', length);
    Sodium.randombytes_buf(bytes, length);
    return Base64.encodeToString(bytes, Base64.DEFAULT).trim();
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
    return Sodium.crypto_aead_chacha20poly1305_keybytes();
  }
  secureSymetricAEADnonceLength(): number {
    return Sodium.crypto_aead_chacha20poly1305_npubbytes();
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
      plainb_bytes.length + Sodium.crypto_aead_chacha20poly1305_abytes()
    );
    const clen_p = Array.create('int', 1);
    const aad_bytes = Base64.decode(aad, Base64.DEFAULT);
    const pnonce_bytes = Base64.decode(pnonce, Base64.DEFAULT);

    // ["decryptSecureSymetricAEAD",{"length":20},{"length":1},{"length":4},4,{"length":3},3,{"length":0},{"length":8},{"length":32}]

    console.log(
      JSON.stringify([
        'decryptSecureSymetricAEAD',
        cipherb,
        clen_p,
        plainb_bytes,
        plainb_bytes.length,
        aad_bytes,
        aad_bytes.length,
        Array.create('byte', 0),
        pnonce_bytes,
        key_bytes
      ])
    );

    if (
      Sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
        cipherb,
        clen_p,
        plainb_bytes,
        plainb_bytes.length,
        aad_bytes,
        aad_bytes.length,
        Array.create('byte', 0),
        pnonce_bytes,
        key_bytes
      ) != 0
    ) {
      throw new Error('Error on crypto_aead_chacha20poly1305_ietf_encrypt');
    }
    return {
      cipherb: Base64.encodeToString(cipherb, Base64.DEFAULT).trim(),
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
      cipherb_bytes.length - Sodium.crypto_aead_chacha20poly1305_abytes()
    );
    const mlen_p = Array.create('int', 1);
    const aad_bytes = Base64.decode(aad, Base64.DEFAULT);
    const pnonce_bytes = Base64.decode(pnonce, Base64.DEFAULT);

    console.log(
      JSON.stringify([
        'decryptSecureSymetricAEAD',
        plaint_bytes,
        mlen_p,
        Array.create('byte', 0),
        cipherb_bytes,
        cipherb_bytes.length,
        aad_bytes,
        aad_bytes.length,
        pnonce_bytes,
        key_bytes
      ])
    );

    // ["decryptSecureSymetricAEAD",{"length":4},{"length":1},{"length":0},{"length":20},20,{"length":4},4,{"length":8},{"length":32}]

    if (
      Sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
        plaint_bytes,
        mlen_p,
        Array.create('byte', 0),
        cipherb_bytes,
        cipherb_bytes.length,
        aad_bytes,
        aad_bytes.length,
        pnonce_bytes,
        key_bytes
      ) != 0
    ) {
      throw new Error('Error on crypto_aead_chacha20poly1305_ietf_decrypt');
    }
    return Base64.encodeToString(
      Arrays.copyOf(plaint_bytes, mlen_p[0]),
      Base64.DEFAULT
    ).trim();
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

    const cipher = new GCMBlockCipher(new AESEngine());
    cipher.init(
      true,
      new AEADParameters(
        new KeyParameter(key_bytes),
        tagLength,
        iv_bytes,
        aad_bytes
      )
    );

    let cipherb = Array.create(
      'byte',
      cipher.getOutputSize(plaint_bytes.length)
    );

    const outputLen = cipher.processBytes(
      plaint_bytes,
      0,
      plaint_bytes.length,
      cipherb,
      0
    );

    cipher.doFinal(cipherb, outputLen);

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

    const cipher = new GCMBlockCipher(new AESEngine());
    cipher.init(
      false,
      new AEADParameters(
        new KeyParameter(key_bytes),
        atag_bytes.length * 8,
        iv_bytes,
        aad_bytes
      )
    );

    let plainb_bytes = Array.create(
      'byte',
      cipher.getOutputSize(cipherb_bytes_complete.length)
    );

    const outputLen = cipher.processBytes(
      cipherb_bytes_complete,
      0,
      cipherb_bytes_complete.length,
      plainb_bytes,
      0
    );

    cipher.doFinal(plainb_bytes, outputLen);

    return Base64.encodeToString(plainb_bytes, Base64.DEFAULT).trim();
  }

  encryptRSA(pub_key_pem: string, plainb: string, padding: string): string {
    if (Object.keys(this.rsaEncPaddingEncodingType).indexOf(padding) === -1) {
      throw new Error(`encryptRSA padding "${padding}" not found!`);
    }
    let _pub_key_pem = pub_key_pem.replace(
      /-----BEGIN PUBLIC KEY-----(\r)*(\n)*/,
      ''
    );
    _pub_key_pem = _pub_key_pem.replace(
      /(\r)*(\n)*-----END PUBLIC KEY-----(\r)*(\n)*/,
      ''
    );
    const public_key_bytes = Base64.decode(_pub_key_pem, Base64.DEFAULT);
    const pub_parameters = PublicKeyFactory.createKey(public_key_bytes);
    const plain_data = Base64.decode(plainb, Base64.DEFAULT);
    let engine;
    if (padding === 'oaep') {
      engine = new this.rsaEncPaddingEncodingType[padding](
        new RSAEngine(),
        new SHA1Digest(),
        new SHA1Digest(),
        null
      );
    } else if (padding === 'pkcs1') {
      engine = new this.rsaEncPaddingEncodingType[padding](new RSAEngine());
    }
    engine.init(true, pub_parameters);
    const encrypted = engine.processBlock(plain_data, 0, plain_data.length);
    return Base64.encodeToString(encrypted, Base64.DEFAULT).trim();
  }
  decryptRSA(priv_key_pem: string, cipherb: string, padding: string): string {
    if (Object.keys(this.rsaEncPaddingEncodingType).indexOf(padding) === -1) {
      throw new Error(`decryptRSA padding "${padding}" not found!`);
    }
    let _priv_key_pem = priv_key_pem.replace(
      /-----BEGIN RSA PRIVATE KEY-----(\r)*(\n)*/,
      ''
    );
    _priv_key_pem = _priv_key_pem.replace(
      /(\r)*(\n)*-----END RSA PRIVATE KEY-----(\r)*(\n)*/,
      ''
    );

    const private_key_bytes = Base64.decode(_priv_key_pem, Base64.DEFAULT);
    const privParameters = PrivateKeyFactory.createKey(private_key_bytes);
    const cipher_data = Base64.decode(cipherb, Base64.DEFAULT);
    let engine;
    if (padding === 'oaep') {
      engine = new this.rsaEncPaddingEncodingType[padding](
        new RSAEngine(),
        new SHA1Digest(),
        new SHA1Digest(),
        null
      );
    } else if (padding === 'pkcs1') {
      engine = new this.rsaEncPaddingEncodingType[padding](new RSAEngine());
    }
    engine.init(false, privParameters);
    const decrypted = engine.processBlock(cipher_data, 0, cipher_data.length);
    return Base64.encodeToString(decrypted, Base64.DEFAULT).trim();
  }
  signRSA(priv_key_pem: string, messageb: string, digest_type: string): string {
    if (Object.keys(this.rsaSigDigestType).indexOf(digest_type) === -1) {
      throw new Error(`signRSA digest type "${digest_type}" not found!`);
    }
    let _priv_key_pem = priv_key_pem.replace(
      /-----BEGIN RSA PRIVATE KEY-----(\r)*(\n)*/,
      ''
    );
    _priv_key_pem = _priv_key_pem.replace(
      /(\r)*(\n)*-----END RSA PRIVATE KEY-----(\r)*(\n)*/,
      ''
    );

    const private_key_bytes = Base64.decode(_priv_key_pem, Base64.DEFAULT);
    const priv_parameters = PrivateKeyFactory.createKey(private_key_bytes);
    const signer = new RSADigestSigner(
      new this.rsaSigDigestType[digest_type]()
    );
    signer.init(true, priv_parameters);
    const message_bytes = Base64.decode(messageb, Base64.DEFAULT);
    signer.update(message_bytes, 0, message_bytes.length);
    const signature_bytes = signer.generateSignature();
    return Base64.encodeToString(signature_bytes, Base64.DEFAULT).trim();
  }
  verifyRSA(
    pub_key_pem: string,
    messageb: string,
    signatureb: string,
    digest_type: string
  ): boolean {
    if (Object.keys(this.rsaSigDigestType).indexOf(digest_type) === -1) {
      throw new Error(`verifyRSA digest type "${digest_type}" not found!`);
    }
    let _pub_key_pem = pub_key_pem.replace(
      /-----BEGIN PUBLIC KEY-----(\r)*(\n)*/,
      ''
    );
    _pub_key_pem = _pub_key_pem.replace(
      /(\r)*(\n)*-----END PUBLIC KEY-----(\r)*(\n)*/,
      ''
    );
    const public_key_bytes = Base64.decode(_pub_key_pem, Base64.DEFAULT);
    const pub_parameters = PublicKeyFactory.createKey(public_key_bytes);
    const signer = new RSADigestSigner(
      new this.rsaSigDigestType[digest_type]()
    );
    signer.init(false, pub_parameters);
    const message_bytes = Base64.decode(messageb, Base64.DEFAULT);
    signer.update(message_bytes, 0, message_bytes.length);
    return signer.verifySignature(Base64.decode(signatureb, Base64.DEFAULT));
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
    return Base64.encodeToString(output, Base64.DEFAULT).trim();
  }
  inflate(input: string): string {
    let data = Base64.decode(input, Base64.DEFAULT);
    let decompresser = new java.util.zip.Inflater();
    decompresser.setInput(data, 0, data.length);
    let output = Array.create('byte', data.length * 20);
    let decompressedDataLength = decompresser.inflate(output);
    decompresser.end();
    output = Arrays.copyOf(output, decompressedDataLength);
    return Base64.encodeToString(output, Base64.DEFAULT).trim();
  }

  base64encode(input: string): string {
    input = new java.lang.String(input).getBytes(StandardCharsets.UTF_8);
    return Base64.encodeToString(input, Base64.DEFAULT).trim();
  }

  base64decode(input: string): string {
    let data = Base64.decode(input, Base64.DEFAULT);
    return new java.lang.String(data, StandardCharsets.UTF_8);
  }

  randomUUID(): string {
    return java.util.UUID.randomUUID().toString();
  }

  keyWrapAES(wrappingKey: string, key: string): string {
    const wrappingKey_bytes = Base64.decode(wrappingKey, Base64.DEFAULT);
    const key_bytes = Base64.decode(key, Base64.DEFAULT);
    const cipher = new KeyWrapEngine(new AESEngine());
    cipher.init(true, new KeyParameter(wrappingKey_bytes));
    const wrappedkey_bytes = cipher.wrap(key_bytes, 0, key_bytes.length);
    return Base64.encodeToString(wrappedkey_bytes, Base64.DEFAULT).trim();
  }
  keyUnWrapAES(unwrappingKey: string, wrappedkey: string): string {
    const unwrappingKey_bytes = Base64.decode(unwrappingKey, Base64.DEFAULT);
    const wrappedkey_bytes = Base64.decode(wrappedkey, Base64.DEFAULT);

    const cipher = new KeyWrapEngine(new AESEngine());
    cipher.init(false, new KeyParameter(unwrappingKey_bytes));
    const key = cipher.unwrap(wrappedkey_bytes, 0, wrappedkey_bytes.length);
    return Base64.encodeToString(key, Base64.DEFAULT).trim();
  }
}
