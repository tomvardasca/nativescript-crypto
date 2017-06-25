import { INSCryto } from './crypto.common';

declare var crypto_hash_sha256: any;
declare var crypto_hash_sha256_bytes: any;
declare var crypto_hash_sha512: any;
declare var crypto_hash_sha512_bytes: any;
declare var sodium_init: any;
declare var crypto_aead_aes256gcm_is_available: any;
declare var randombytes_uniform: any;
declare var randombytes_buf: any;
declare var crypto_box_seedbytes: any;
declare var crypto_pwhash_alg_argon2i13: any;
declare var crypto_pwhash_argon2i: any;
declare var crypto_pwhash_argon2i_saltbytes: any;
declare var crypto_pwhash_scryptsalsa208sha256: any;
declare var crypto_pwhash_scryptsalsa208sha256_saltbytes: any;
declare var crypto_aead_aes256gcm_encrypt: any;
declare var crypto_aead_aes256gcm_decrypt: any;
declare var crypto_aead_aes256gcm_abytes: any;
declare var crypto_aead_aes256gcm_keybytes: any;
declare var crypto_aead_aes256gcm_npubbytes: any;
declare var crypto_aead_chacha20poly1305_ietf_encrypt: any;
declare var crypto_aead_chacha20poly1305_ietf_decrypt: any;
declare var crypto_aead_chacha20poly1305_ietf_abytes: any;
declare var crypto_aead_chacha20poly1305_ietf_keybytes: any;
declare var crypto_aead_chacha20poly1305_ietf_npubbytes: any;

declare var IAGAesGcm: any;
declare var IAGCipheredData: any;
declare var cipheredDataByAuthenticatedEncryptingPlainDataWithAdditionalAuthenticatedDataAuthenticationTagLengthInitializationVectorKeyError: any;
declare var plainDataByAuthenticatedDecryptingCipheredDataWithAdditionalAuthenticatedDataInitializationVectorKeyError: any;

declare var ClearMessage: any;
declare var EncryptedMessage: any;
declare var PrivateKey: any;
declare var PublicKey: any;
declare var DigestType: any;
declare var Signature: any;

const toBase64 = (input: interop.Pointer, length: number): string => {
  const data = NSData.dataWithBytesLength(input, length);
  const base64 = data.base64EncodedStringWithOptions(0);
  return base64;
};

const base64toBytes = (
  input: string
): { bytes: interop.AdoptedPointer; length: number } => {
  let input_data = new NSData({ base64Encoding: input });
  let _input_length = input_data.length;
  let _input = interop.alloc(
    _input_length * interop.sizeof(interop.types.unichar)
  );
  input_data.getBytes(_input);
  return { bytes: _input, length: _input_length };
};

export class NSCrypto implements INSCryto {
  private crypto_pwhash_consts = {
    scryptsalsa208sha256: {
      mem_limits: {
        min: 8192 * 7168,
        max: 8192 * 9126
      },
      ops_limits: {
        min: 768 * 512,
        max: 768 * 768
      }
    },
    argon2i: {
      mem_limits: {
        min: 8192 * 308,
        max: 8192 * 436
      },
      ops_limits: {
        min: 4,
        max: 6
      }
    }
  };

  private hashTypeLibsodiumFn = {
    sha256: {
      hashFn: crypto_hash_sha256,
      bytesFn: crypto_hash_sha256_bytes
    },
    sha512: {
      hashFn: crypto_hash_sha512,
      bytesFn: crypto_hash_sha512_bytes
    }
  };

  private rsaEncPaddingType = {
    pkcs1: SecPadding.kSecPaddingPKCS1,
    oaep: SecPadding.kSecPaddingOAEP
  };

  private rsaSigDigestType = {
    sha1: DigestType.Sha1,
    sha256: DigestType.Sha256,
    sha512: DigestType.Sha512
  };

  hash(input: string, type: string): string {
    if (Object.keys(this.hashTypeLibsodiumFn).indexOf(type) === -1) {
      throw new Error(`hash type "${type}" not found!`);
    }
    sodium_init();
    let hash_libsodium_fns = this.hashTypeLibsodiumFn[type];
    let hash = interop.alloc(
      hash_libsodium_fns.bytesFn() * interop.sizeof(interop.types.unichar)
    );
    hash_libsodium_fns.hashFn(hash, input, input.length);
    return toBase64(hash, hash_libsodium_fns.bytesFn());
  }

  secureRandomBytes(length: number): string {
    sodium_init();
    let bytes = interop.alloc(length * interop.sizeof(interop.types.unichar));
    randombytes_buf(bytes, length);
    return toBase64(bytes, length);
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
    sodium_init();
    let _salt;
    let _salt_length = -1;
    if (salt) {
      let salt_data = new NSData({ base64Encoding: salt });
      _salt_length = salt_data.length;
      _salt = interop.alloc(
        _salt_length * interop.sizeof(interop.types.unichar)
      );
      salt_data.getBytes(_salt);
    }
    alg = alg || 'argon2i';

    let crypto_pwhash_fn = crypto_pwhash_argon2i;
    let crypto_pwhash_saltbytes_fn = crypto_pwhash_argon2i_saltbytes;

    if (alg === 'scryptsalsa208sha256') {
      // conversion needed crypto_pwhash_scryptsalsa208sha256 dont have alg parameter
      crypto_pwhash_fn = function() {
        let new_args = [];
        for (let i = 0; i < arguments.length - 1; i++) {
          new_args.push(arguments[i]);
        }
        return crypto_pwhash_scryptsalsa208sha256(...new_args);
      };
      crypto_pwhash_saltbytes_fn = crypto_pwhash_scryptsalsa208sha256_saltbytes;
    } else if (alg !== 'argon2i') {
      throw new Error(`deriveSecureKey algorithm "${alg}" not found`);
    }
    if (!mem_limits) {
      let diff =
        this.crypto_pwhash_consts[alg].mem_limits.max -
        this.crypto_pwhash_consts[alg].mem_limits.min;
      mem_limits =
        this.crypto_pwhash_consts[alg].mem_limits.min +
        randombytes_uniform(diff + 1); // randombytes_uniform upper_bound is (excluded)
    }
    if (!ops_limits) {
      let diff =
        this.crypto_pwhash_consts[alg].ops_limits.max -
        this.crypto_pwhash_consts[alg].ops_limits.min;
      ops_limits =
        this.crypto_pwhash_consts[alg].ops_limits.min +
        randombytes_uniform(diff + 1); // randombytes_uniform upper_bound is (excluded)
    }

    if (_salt_length === -1) {
      _salt_length = crypto_pwhash_saltbytes_fn();
      _salt = interop.alloc(
        _salt_length * interop.sizeof(interop.types.unichar)
      );
      randombytes_buf(_salt, _salt_length);
    }
    let derived_key = interop.alloc(
      key_size * interop.sizeof(interop.types.unichar)
    );
    if (
      crypto_pwhash_fn(
        derived_key,
        key_size,
        password,
        password.length,
        _salt,
        ops_limits,
        mem_limits,
        crypto_pwhash_alg_argon2i13()
      ) !== 0
    ) {
      throw new Error('deriveSecureKey out of memory');
    }
    return {
      key: toBase64(derived_key, key_size),
      salt: toBase64(_salt, _salt_length),
      ops_limits: ops_limits,
      mem_limits: mem_limits,
      alg: alg
    };
  }
  secureSymetricAEADkeyLength(): number {
    if (crypto_aead_aes256gcm_is_available() !== 0) {
      return crypto_aead_aes256gcm_keybytes();
    }
    return crypto_aead_chacha20poly1305_ietf_keybytes();
  }
  secureSymetricAEADnonceLength(): number {
    if (crypto_aead_aes256gcm_is_available() !== 0) {
      return crypto_aead_aes256gcm_npubbytes();
    }
    return crypto_aead_chacha20poly1305_ietf_npubbytes();
  }
  encryptSecureSymetricAEAD(
    key: string,
    plaint: string,
    aad: string,
    pnonce: string,
    alg?: string
  ): { cipherb: string; alg: string } {
    let ciphert;
    let cipherb_length = new interop.Reference<number>();

    if (
      crypto_aead_aes256gcm_is_available() !== 0 &&
      (alg === 'aes256gcm' || !alg)
    ) {
      ciphert = interop.alloc(
        (plaint.length + crypto_aead_aes256gcm_abytes()) *
          interop.sizeof(interop.types.unichar)
      );
      crypto_aead_aes256gcm_encrypt(
        ciphert,
        cipherb_length,
        plaint,
        plaint.length,
        aad,
        aad.length,
        null,
        base64toBytes(pnonce).bytes,
        base64toBytes(key).bytes
      );
      return {
        cipherb: toBase64(ciphert, cipherb_length.value),
        alg: 'aes256gcm'
      };
    } else if (alg === 'chacha20poly1305_ietf' || !alg) {
      ciphert = interop.alloc(
        (plaint.length + crypto_aead_chacha20poly1305_ietf_abytes()) *
          interop.sizeof(interop.types.unichar)
      );
      crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphert,
        cipherb_length,
        plaint,
        plaint.length,
        aad,
        aad.length,
        null,
        base64toBytes(pnonce).bytes,
        base64toBytes(key).bytes
      );
      return {
        cipherb: toBase64(ciphert, cipherb_length.value),
        alg: 'chacha20poly1305_ietf'
      };
    } else {
      throw new Error(
        `encryptSecureSymetricAEAD algorith ${alg} not found or is not available in this hardware`
      );
    }
  }
  decryptSecureSymetricAEAD(
    key: string,
    cipherb: string,
    aad: string,
    pnonce: string,
    alg?: string
  ): string {
    let plaint: interop.Pointer;
    let plaint_length = new interop.Reference<number>();

    if (
      crypto_aead_aes256gcm_is_available() !== 0 &&
      (alg === 'aes256gcm' || !alg)
    ) {
      let cipherb_p = base64toBytes(cipherb);
      plaint = interop.alloc(
        (cipherb_p.length - crypto_aead_chacha20poly1305_ietf_abytes()) *
          interop.sizeof(interop.types.unichar)
      );
      crypto_aead_aes256gcm_decrypt(
        plaint,
        plaint_length,
        cipherb_p,
        cipherb_p.length,
        aad,
        aad.length,
        null,
        base64toBytes(pnonce).bytes,
        base64toBytes(key).bytes
      );
    } else if (alg === 'chacha20poly1305_ietf' || !alg) {
      plaint = interop.alloc(
        cipherb.length * interop.sizeof(interop.types.unichar)
      );
      crypto_aead_chacha20poly1305_ietf_decrypt(
        plaint,
        plaint_length,
        cipherb,
        cipherb.length,
        aad,
        aad.length,
        null,
        base64toBytes(pnonce).bytes,
        base64toBytes(key).bytes
      );
    } else {
      throw new Error(
        `decryptSecureSymetricAEAD algorith ${alg} not found or is not available in this hardware`
      );
    }
    return <any>new NSString({
      bytes: plaint,
      length: plaint_length.value,
      encoding: NSUTF8StringEncoding
    });
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
    let plaintData: NSData = new NSString({
      UTF8String: plaint
    }).dataUsingEncoding(NSUTF8StringEncoding);
    let aadData: NSData = new NSString({
      UTF8String: aad
    }).dataUsingEncoding(NSUTF8StringEncoding);
    let ivData = new NSData({
      base64EncodedString: iv,
      options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters
    });
    let keyData = new NSData({
      base64EncodedString: key,
      options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters
    });
    let cipheredData = cipheredDataByAuthenticatedEncryptingPlainDataWithAdditionalAuthenticatedDataAuthenticationTagLengthInitializationVectorKeyError(
      plaintData,
      aadData,
      ivData,
      keyData
    );
    return {
      cipherb: toBase64(
        cipheredData.cipheredBuffer,
        cipheredData.cipheredBufferLength
      ),
      atag: toBase64(
        cipheredData.authenticationTag,
        cipheredData.authenticationTagLength
      )
    };
  }
  decryptAES256GCM(
    key: string,
    cipherb: string,
    aad: string,
    iv: string,
    atag: string
  ): string {
    let cipherb_p = base64toBytes(cipherb);
    let atag_p = base64toBytes(cipherb);
    let cipheredData = new IAGCipheredData({
      cipheredBuffer: cipherb_p.bytes,
      cipheredBufferLength: cipherb_p.length,
      authenticationTag: atag_p.bytes,
      authenticationTagLength: atag_p.length
    });
    let aadData: NSData = new NSString({
      UTF8String: aad
    }).dataUsingEncoding(NSUTF8StringEncoding);
    let ivData = new NSData({
      base64EncodedString: iv,
      options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters
    });
    let keyData = new NSData({
      base64EncodedString: key,
      options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters
    });

    let plaintData = plainDataByAuthenticatedDecryptingCipheredDataWithAdditionalAuthenticatedDataInitializationVectorKeyError(
      cipheredData,
      aadData,
      ivData,
      keyData
    );
    return <any>new NSString({
      data: plaintData,
      encoding: NSUTF8StringEncoding
    });
  }
  encryptRSA(pub_key_pem: string, plainb: string, padding: string): string {
    if (Object.keys(this.rsaEncPaddingType).indexOf(padding) === -1) {
      throw new Error(`encryptRSA padding "${padding}" not found!`);
    }
    let pubKey = new PublicKey({ pemEncoded: pub_key_pem });
    let clearMessage = new ClearMessage({
      base64Encoded: plainb
    });
    let encryptedMessage = clearMessage.encryptedWithPaddingError(
      pubKey,
      SecPadding.kSecPaddingOAEP
    );
    return encryptedMessage.base64String;
  }
  decryptRSA(priv_key_pem: string, cipherb: string, padding: string): string {
    if (Object.keys(this.rsaEncPaddingType).indexOf(padding) === -1) {
      throw new Error(`decryptRSA padding "${padding}" not found!`);
    }
    let privKey = new PrivateKey({ pemEncoded: priv_key_pem });
    let encryptedMessage = new EncryptedMessage({
      base64Encoded: cipherb
    });
    let clearMessage = encryptedMessage.decryptedWithPaddingError(
      privKey,
      SecPadding.kSecPaddingOAEP
    );
    return clearMessage.base64String;
  }
  signRSA(priv_key_pem: string, messageb: string, digest_type: string): string {
    if (Object.keys(this.rsaSigDigestType).indexOf(digest_type) === -1) {
      throw new Error(`decryptRSA digest type "${digest_type}" not found!`);
    }
    let privKey = new PrivateKey({ pemEncoded: priv_key_pem });
    let clearMessage = new ClearMessage({
      base64Encoded: messageb
    });
    let signature = clearMessage.signedWithDigestTypeError(
      privKey,
      this.rsaSigDigestType[digest_type]
    );
    return signature.base64String;
  }
  verifyRSA(
    pub_key_pem: string,
    messageb: string,
    signatureb: string,
    digest_type: string
  ): boolean {
    if (Object.keys(this.rsaSigDigestType).indexOf(digest_type) === -1) {
      throw new Error(`decryptRSA digest type "${digest_type}" not found!`);
    }
    let pubKey = new PublicKey({ pemEncoded: pub_key_pem });
    let clearMessage = new ClearMessage({
      base64Encoded: messageb
    });
    let signature = new Signature({
      base64Encoded: signatureb
    });
    let verificationResult = clearMessage.verifyWithSignatureDigestTypeError(
      pubKey,
      signature,
      this.rsaSigDigestType[digest_type]
    );
    return verificationResult.isSuccessful;
  }

  deflate(input: string, alg?: string): string {
    let _alg = compression_algorithm.COMPRESSION_ZLIB;
    if (alg === 'lzfse') {
      _alg = compression_algorithm.COMPRESSION_LZFSE;
    }
    let dest_buffer = interop.alloc(
      input.length * interop.sizeof(interop.types.unichar)
    );
    let dest_size = compression_encode_buffer(
      <any>dest_buffer,
      input.length + 4096,
      input,
      input.length,
      null,
      _alg
    );
    return toBase64(dest_buffer, dest_size);
  }
  inflate(input: string, alg?: string): string {
    let _alg = compression_algorithm.COMPRESSION_ZLIB;
    let ratio = 20;
    if (alg === 'lzfse') {
      _alg = compression_algorithm.COMPRESSION_LZFSE;
    }

    let data = new NSData({
      base64EncodedString: input,
      options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters
    });
    let src_buffer = interop.alloc(
      data.length * interop.sizeof(interop.types.unichar)
    );
    data.getBytes(src_buffer);
    let dest_buffer = interop.alloc(
      data.length * ratio * interop.sizeof(interop.types.unichar)
    );
    let dest_size = compression_decode_buffer(
      <any>dest_buffer,
      data.length * ratio + 4096,
      <any>src_buffer,
      input.length,
      null,
      _alg
    );
    let str = new NSString({
      bytes: dest_buffer,
      length: dest_size,
      encoding: NSUTF8StringEncoding
    });
    return <any>str;
  }

  base64encode(input: string): string {
    let plainData: NSData = new NSString({
      UTF8String: input
    }).dataUsingEncoding(NSUTF8StringEncoding);
    return plainData.base64EncodedStringWithOptions(kNilOptions);
  }
  base64decode(input: string): string {
    let data = new NSData({
      base64EncodedString: input,
      options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters
    });
    return <any>new NSString({
      data: data,
      encoding: NSUTF8StringEncoding
    });
  }
}
