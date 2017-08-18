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
declare var ClearMessage: any;
declare var EncryptedMessage: any;
declare var PrivateKey: any;
declare var PublicKey: any;
declare var DigestType: any;
declare var Signature: any;
declare var IAGAuthenticationTagLength128: any;

declare var DataCompression: any;

declare var SwKeyWrap: any;
declare var SwCC: any;
declare var SwCC_OpMode: any;
declare var SwCC_Algorithm: any;
declare var SwCC_AuthBlockMode: any;

declare var SwRSA: any;
declare var SwKeyConvert_PublicKey: any;
declare var SwKeyConvert_PrivateKey: any;
declare var SwRSA_AsymmetricPadding: any;
declare var SwCC_DigestAlgorithm: any;
declare var SwRSA_AsymmetricSAPadding: any;

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
      mem_limits: { min: 8192 * 7168, max: 8192 * 9126 },
      ops_limits: { min: 768 * 512, max: 768 * 768 }
    },
    argon2i: {
      mem_limits: { min: 8192 * 308, max: 8192 * 436 },
      ops_limits: { min: 4, max: 6 }
    }
  };

  private rsaEncPaddingType = {
    pkcs1: SwRSA_AsymmetricPadding.Pkcs1,
    oaep: SwRSA_AsymmetricPadding.Oaep
  };

  private digestType = {
    sha1: SwCC_DigestAlgorithm.Sha1,
    sha256: SwCC_DigestAlgorithm.Sha256,
    sha512: SwCC_DigestAlgorithm.Sha512
  };

  hash(input: string, type: string): string {
    if (Object.keys(this.digestType).indexOf(type) === -1) {
      throw new Error(`hash type "${type}" not found!`);
    }
    let inputData: NSData = new NSData({
      base64EncodedString: input,
      options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters
    });
    return SwCC.digestAlg(
      inputData,
      this.digestType[type]
    ).base64EncodedStringWithOptions(kNilOptions);
  }

  secureRandomBytes(length: number): string {
    return SwCC.generateRandom(length).base64EncodedStringWithOptions(
      kNilOptions
    );
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
    if (['argon2i', 'scryptsalsa208sha256'].indexOf(alg) === -1) {
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
      if (alg === 'argon2i') {
        _salt_length = crypto_pwhash_argon2i_saltbytes();
      } else if (alg === 'argon2i') {
        _salt_length = crypto_pwhash_scryptsalsa208sha256_saltbytes();
      }
      _salt = interop.alloc(
        _salt_length * interop.sizeof(interop.types.unichar)
      );
      randombytes_buf(_salt, _salt_length);
    }
    let derived_key = interop.alloc(
      key_size * interop.sizeof(interop.types.unichar)
    );

    if (alg === 'argon2i') {
      if (
        crypto_pwhash_argon2i(
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
    } else if (alg === 'scryptsalsa208sha256') {
      if (
        crypto_pwhash_scryptsalsa208sha256(
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
    plainb: string,
    aad: string,
    pnonce: string,
    alg?: string
  ): { cipherb: string; alg: string } {
    let cipherb;
    let cipherb_length = new interop.Reference<number>();
    let dataPlainb = base64toBytes(plainb);
    let dataAAD = base64toBytes(aad);

    if (
      crypto_aead_aes256gcm_is_available() !== 0 &&
      (alg === 'aes256gcm' || !alg)
    ) {
      cipherb = interop.alloc(
        (dataPlainb.length + crypto_aead_aes256gcm_abytes()) *
          interop.sizeof(interop.types.unichar)
      );
      crypto_aead_aes256gcm_encrypt(
        cipherb,
        cipherb_length,
        dataPlainb.bytes,
        dataPlainb.length,
        dataAAD.bytes,
        dataAAD.length,
        null,
        base64toBytes(pnonce).bytes,
        base64toBytes(key).bytes
      );
      return {
        cipherb: toBase64(cipherb, cipherb_length.value),
        alg: 'aes256gcm'
      };
    } else if (alg === 'chacha20poly1305_ietf' || !alg) {
      cipherb = interop.alloc(
        (plainb.length + crypto_aead_chacha20poly1305_ietf_abytes()) *
          interop.sizeof(interop.types.unichar)
      );
      crypto_aead_chacha20poly1305_ietf_encrypt(
        cipherb,
        cipherb_length,
        dataPlainb.bytes,
        dataPlainb.length,
        dataAAD.bytes,
        dataAAD.length,
        null,
        base64toBytes(pnonce).bytes,
        base64toBytes(key).bytes
      );
      return {
        cipherb: toBase64(cipherb, cipherb_length.value),
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
    let plainb: interop.Pointer;
    let plainb_length = new interop.Reference<number>();

    if (
      crypto_aead_aes256gcm_is_available() !== 0 &&
      (alg === 'aes256gcm' || !alg)
    ) {
      let cipherb_p = base64toBytes(cipherb);
      plainb = interop.alloc(
        (cipherb_p.length - crypto_aead_chacha20poly1305_ietf_abytes()) *
          interop.sizeof(interop.types.unichar)
      );
      crypto_aead_aes256gcm_decrypt(
        plainb,
        plainb_length,
        cipherb_p,
        cipherb_p.length,
        aad,
        aad.length,
        null,
        base64toBytes(pnonce).bytes,
        base64toBytes(key).bytes
      );
    } else if (alg === 'chacha20poly1305_ietf' || !alg) {
      plainb = interop.alloc(
        cipherb.length * interop.sizeof(interop.types.unichar)
      );
      crypto_aead_chacha20poly1305_ietf_decrypt(
        plainb,
        plainb_length,
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
    return toBase64(plainb, plainb_length.value);
  }

  encryptAES256GCM(
    key: string,
    plainb: string,
    aad: string,
    iv: string,
    tagLength: number = 128
  ): { cipherb: string; atag: string } {
    let plaintData = new NSData({ base64Encoding: plainb });
    let aadData = new NSData({ base64Encoding: aad });
    let ivData = new NSData({ base64Encoding: iv });
    let keyData = new NSData({ base64Encoding: key });

    let res = SwCC.cryptAuthBlockModeAlgorithmDataADataKeyIvTagLengthTagError(
      SwCC_OpMode.Encrypt,
      SwCC_AuthBlockMode.Gcm,
      SwCC_Algorithm.Aes,
      plaintData,
      aadData,
      keyData,
      ivData,
      tagLength / 8,
      null
    );

    return {
      cipherb: res
        .valueForKey('data')
        .base64EncodedStringWithOptions(kNilOptions),
      atag: res.valueForKey('tag').base64EncodedStringWithOptions(kNilOptions)
    };
  }
  decryptAES256GCM(
    key: string,
    cipherb: string,
    aad: string,
    iv: string,
    atag: string
  ): string {
    let cipherbData: NSData = new NSData({
      base64EncodedString: cipherb,
      options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters
    });
    let atagData: NSData = new NSData({
      base64EncodedString: atag,
      options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters
    });
    let aadData: NSData = new NSData({
      base64EncodedString: aad,
      options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters
    });
    let ivData = new NSData({
      base64EncodedString: iv,
      options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters
    });
    let keyData = new NSData({
      base64EncodedString: key,
      options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters
    });

    let res = SwCC.cryptAuthBlockModeAlgorithmDataADataKeyIvTagLengthTagError(
      SwCC_OpMode.Decrypt,
      SwCC_AuthBlockMode.Gcm,
      SwCC_Algorithm.Aes,
      cipherbData,
      aadData,
      keyData,
      ivData,
      atagData.length,
      atagData
    );
    return res.valueForKey('data').base64EncodedStringWithOptions(kNilOptions);
  }
  encryptRSA(pub_key_pem: string, plainb: string, padding: string): string {
    if (Object.keys(this.rsaEncPaddingType).indexOf(padding) === -1) {
      throw new Error(`encryptRSA padding "${padding}" not found!`);
    }
    let plainbData: NSData = new NSData({
      base64EncodedString: plainb,
      options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters
    });
    const derKey = SwKeyConvert_PublicKey.pemToPKCS1DERError(pub_key_pem);
    return SwRSA.encryptDerKeyTagPaddingDigestError(
      plainbData,
      derKey,
      null,
      this.rsaEncPaddingType[padding],
      SwCC_DigestAlgorithm.Sha1
    ).base64EncodedStringWithOptions(kNilOptions);
  }
  decryptRSA(priv_key_pem: string, cipherb: string, padding: string): string {
    if (Object.keys(this.rsaEncPaddingType).indexOf(padding) === -1) {
      throw new Error(`decryptRSA padding "${padding}" not found!`);
    }
    let cipherbData: NSData = new NSData({
      base64EncodedString: cipherb,
      options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters
    });
    const derKey = SwKeyConvert_PrivateKey.pemToPKCS1DERError(priv_key_pem);
    return SwRSA.decryptDerKeyTagPaddingDigestError(
      cipherbData,
      derKey,
      null,
      this.rsaEncPaddingType[padding],
      SwCC_DigestAlgorithm.Sha1
    ).base64EncodedStringWithOptions(kNilOptions);
  }

  signRSA(priv_key_pem: string, messageb: string, digest_type: string): string {
    if (Object.keys(this.digestType).indexOf(digest_type) === -1) {
      throw new Error(`signRSA digest type "${digest_type}" not found!`);
    }
    let messagebData: NSData = new NSData({
      base64EncodedString: messageb,
      options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters
    });
    const derKey = SwKeyConvert_PrivateKey.pemToPKCS1DERError(priv_key_pem);
    return SwRSA.signDerKeyPaddingDigestSaltLenError(
      messagebData,
      derKey,
      SwRSA_AsymmetricSAPadding.Pkcs15,
      SwCC_DigestAlgorithm.Sha256,
      0,
      null
    ).base64EncodedStringWithOptions(kNilOptions);
    //  let privKey = new PrivateKey({ pemEncoded: priv_key_pem });
    // let clearMessage = new ClearMessage({
    //   base64Encoded: messageb
    // });
    // let signature = clearMessage.signedWithDigestTypeError(
    //   privKey,
    //   this.rsaSigDigestType[digest_type]
    // );
    // return signature.base64String;
  }

  verifyRSA(
    pub_key_pem: string,
    messageb: string,
    signatureb: string,
    digest_type: string
  ): boolean {
    if (Object.keys(this.digestType).indexOf(digest_type) === -1) {
      throw new Error(`verifyRSA digest type "${digest_type}" not found!`);
    }
    let messagebData: NSData = new NSData({
      base64EncodedString: messageb,
      options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters
    });
    let signaturebData: NSData = new NSData({
      base64EncodedString: signatureb,
      options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters
    });
    const derKey = SwKeyConvert_PublicKey.pemToPKCS1DERError(pub_key_pem);
    try {
      return (
        SwRSA.verifyDerKeyPaddingDigestSaltLenSignedDataError(
          messagebData,
          derKey,
          SwRSA_AsymmetricSAPadding.Pkcs15,
          SwCC_DigestAlgorithm.Sha256,
          0,
          signaturebData,
          null
        ) == 1
      );
    } catch (err) {
      return false;
    }
    // let pubKey = new PublicKey({ pemEncoded: pub_key_pem });
    // let clearMessage = new ClearMessage({
    //   base64Encoded: messageb
    // });
    // let signature = new Signature({ base64Encoded: signatureb });
    // let verificationResult = clearMessage.verifyWithSignatureDigestTypeError(
    //   pubKey,
    //   signature,
    //   this.rsaSigDigestType[digest_type]
    // );
    // return verificationResult.isSuccessful;
  }

  deflate(input: string, alg?: string): string {
    let data = new NSData({
      base64EncodedString: input,
      options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters
    });
    let dc = new DataCompression({ data });
    return dc.zip().base64EncodedStringWithOptions(kNilOptions);
  }
  inflate(input: string, alg?: string): string {
    let data = new NSData({
      base64EncodedString: input,
      options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters
    });
    let dc = new DataCompression({ data });
    return dc
      .unzipWithSkipHeaderAndCheckSumValidation(true)
      .base64EncodedStringWithOptions(kNilOptions);
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

  randomUUID(): string {
    return NSUUID.UUID().UUIDString;
  }

  keyWrapAES(wrappingKey: string, key: string): string {
    let wrappingKeyData = new NSData({
      base64EncodedString: wrappingKey,
      options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters
    });
    let keyData = new NSData({
      base64EncodedString: key,
      options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters
    });
    return SwKeyWrap.SymmetricKeyWrapKekRawKeyError(
      SwKeyWrap.rfc3394IV,
      wrappingKeyData,
      keyData,
      null
    ).base64EncodedStringWithOptions(kNilOptions);
  }
  keyUnWrapAES(unwrappingKey: string, wrappedkey: string): string {
    let unwrappingKeyData = new NSData({
      base64EncodedString: unwrappingKey,
      options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters
    });
    let wrappedData = new NSData({
      base64EncodedString: wrappedkey,
      options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters
    });
    return SwKeyWrap.SymmetricKeyUnwrapKekWrappedKeyError(
      SwKeyWrap.rfc3394IV,
      unwrappingKeyData,
      wrappedData,
      null
    ).base64EncodedStringWithOptions(kNilOptions);
  }
}
