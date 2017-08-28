import * as observable from 'tns-core-modules/data/observable';
import * as pages from 'tns-core-modules/ui/page';

import { HelloWorldModel } from './main-view-model';
import { NSCrypto } from 'nativescript-crypto';
import * as utils from './utils';

import * as pako from 'pako';

let helloWorldModel: HelloWorldModel;
// Event handler for Page 'loaded' event attached in main-page.xml
export function pageLoaded(args: observable.EventData) {
  // Get the event sender
  let page = <pages.Page>args.object;
  helloWorldModel = new HelloWorldModel();
  page.bindingContext = helloWorldModel;
}

const crypto = new NSCrypto();

export function deflate_inflate() {
  let start = new Date().getTime();
  console.log(
    'crypto..inflate-nativo:',
    '| native deflate ->',
    crypto.deflate(crypto.base64encode('abc')),
    '| pako deflate ->',
    utils.asciiToBase64(pako.deflate('abc', { to: 'string' })),
    '| native deflate > pako inflate ->',
    pako.inflate(
      utils.base64ToASCII(crypto.deflate(crypto.base64encode('abc'))),
      { to: 'string' }
    ),
    '| native inflate ->',
    crypto.inflate(utils.asciiToBase64(pako.deflate('abc', { to: 'string' }))),
    '| pako inflate ->',
    pako.inflate(
      utils.base64ToASCII(crypto.deflate(crypto.base64encode('abc'))),
      { to: 'string' }
    ),
    // crypto.base64encode(pako.deflate('abc', { to: 'string' })),
    // crypto.base64encode(pako.deflate('123456', { to: 'string' })),
    // crypto.base64encode(pako.deflate('sddddadsadas', { to: 'string' })),
    // crypto.base64encode(
    //   pako.deflate('213871298381ds,jhsdbhbcasdbfhjkb874723', { to: 'string' })
    // ),
    ' elapsed ',
    new Date().getTime() - start + 'ms'
  );
  console.log(new Date().getTime() - start + 'ms');

  // start = new Date().getTime();
  // console.log(
  //   'crypto.inflate-js:',
  //   // pako.inflate(
  //   // crypto.base64decode(crypto.deflate(crypto.base64encode('abc'))),
  //   // //   { to: 'string' }
  //   // //),
  //   crypto.base64encode(pako.deflate('abc', { to: 'string' })),
  //   // crypto.base64encode(pako.deflate('abc', { to: 'string' })),
  //   // crypto.base64encode(pako.deflate('123456', { to: 'string' })),
  //   // crypto.base64encode(pako.deflate('sddddadsadas', { to: 'string' })),
  //   // crypto.base64encode(
  //   //   pako.deflate('213871298381ds,jhsdbhbcasdbfhjkb874723', { to: 'string' })
  //   // ),
  //   ' elapsed '
  // );
  // console.log(new Date().getTime() - start + 'ms');

  let benchSTR = '';
  const possible =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < 1000000; i++) {
    benchSTR += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  const benchSTRb64 = crypto.base64encode(benchSTR);

  start = new Date().getTime();
  const nativeDef = crypto.deflate(benchSTRb64);
  let durationNative = new Date().getTime() - start;
  console.log('crypto.deflate-nativo:', durationNative + 'ms');
  start = new Date().getTime();
  const pakoDef = pako.deflate(benchSTR);
  let durationPako = new Date().getTime() - start;
  console.log('crypto.deflate-pako:', durationPako + 'ms');
  console.log('deflate improvement:', durationPako / durationNative + 'x');
  start = new Date().getTime();
  crypto.inflate(nativeDef);
  durationNative = new Date().getTime() - start;
  console.log('crypto.inflate-nativo:', durationNative + 'ms');
  start = new Date().getTime();
  pako.inflate(pakoDef);
  durationPako = new Date().getTime() - start;
  console.log('crypto.inflate-pako:', durationPako + 'ms');
  console.log('inflate improvement:', durationPako / durationNative + 'x');
}

export function sha256() {
  let start = new Date().getTime();
  console.log(
    'crypto.hash 256:',
    crypto.hash(crypto.base64encode('abc'), 'sha256'),
    ' elapsed ',
    new Date().getTime() - start + 'ms'
  );
}

export function random() {
  let start = new Date().getTime();
  console.log(
    'crypto.random: ',
    crypto.secureRandomBytes(32),
    ' elapsed ',
    new Date().getTime() - start + 'ms'
  );
}

export function deriveSecureKey() {
  let start = new Date().getTime();
  console.log(
    'crypto.deriveSecureKey: ',
    JSON.stringify(
      crypto.deriveSecureKey(
        '123456',
        32,
        null,
        null,
        null // ,
        // "scryptsalsa208sha256"
      )
    ),
    ' elapsed ',
    new Date().getTime() - start + 'ms'
  );
}

export function encryptRSA() {
  let start = new Date().getTime();
  let enc = crypto.encryptRSA(
    //     `-----BEGIN PUBLIC KEY-----
    // MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyYkXNjFBK1Am+XX6p31C
    // E6Il41Swr/Wgd23B6oIvcWMv+JRnTZijB86T9tipOOnd2xKjkP0R19KN1rlCOsKN
    // bbN7eL5BZPtseDoBoEEU/LWTvgn+eMWykSSb/31OqCa29HT7wB8K8k1SvkhhrP/E
    // f3mKE8dRt1rPBDdKW7ZeyztP1v9s1vRPPkSkVSNAnlniecdaKz/mNT0yNUvl8ra+
    // CcGBRPTt3MKLRCOpA8oGckMkGEYBC9MFdICEuu2Jj9d8ay7tL4zQ6Iyg+jkqiz2o
    // 4ib6QwUp1++zv+QDTDwong5HLANrNaSwkHEG6fIY+09KPBMR0DhonsK53uHPHBLm
    // tQIDAQAB
    // -----END PUBLIC KEY-----`,
    `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs9VMXCDY1IyyinC+GRsC
4VkDp4LKV1dXSQyNGxodT5278H9+/SPaKakFG5tKVWvlqX3wyXq1OfXBeEAKiAy6
2nKWppCTq7rEa0+iChy2fl4uE/qydgyLgBoTqK4Rl1uob9tjiKdDKCp1+WHWFmnQ
8gAZwJparazFOCW/KoLyVEMxtx/2eWoeXzef40Qo+lm1viLQnwQ6qmEiaRgLGIpK
w8fhS5arj1JZid9jZSTAlVsec0IQQGvFUjvKBQBrV/vjwM4oO3TKpyjTEtyXYtGS
ToHZka3oruXY9nFSt/5sFcsrYjYPsdYB9ybI43zm5jYOPzKKSzMkeweu9KVjC6Lx
PQIDAQAB
-----END PUBLIC KEY-----
`,
    'bHFKkSoHAYbMMg5IkgturPZe1BAaw8GLSOQeZjhQ2U4=',
    'oaep'
  );
  console.log(
    'crypto.encryptRSA: ',
    '123',
    crypto.base64encode('123'),
    enc,
    ' elapsed ',
    new Date().getTime() - start + 'ms'
  );
  start = new Date().getTime();
  let dec = crypto.decryptRSA(
    `-----BEGIN RSA PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDJiRc2MUErUCb5
dfqnfUIToiXjVLCv9aB3bcHqgi9xYy/4lGdNmKMHzpP22Kk46d3bEqOQ/RHX0o3W
uUI6wo1ts3t4vkFk+2x4OgGgQRT8tZO+Cf54xbKRJJv/fU6oJrb0dPvAHwryTVK+
SGGs/8R/eYoTx1G3Ws8EN0pbtl7LO0/W/2zW9E8+RKRVI0CeWeJ5x1orP+Y1PTI1
S+Xytr4JwYFE9O3cwotEI6kDygZyQyQYRgEL0wV0gIS67YmP13xrLu0vjNDojKD6
OSqLPajiJvpDBSnX77O/5ANMPCieDkcsA2s1pLCQcQbp8hj7T0o8ExHQOGiewrne
4c8cEua1AgMBAAECggEAFrmssmGvdZDeNDcHgqdvMgOQvieonM7Xv1/TA/yWGPUU
TbV+SJOznoe+y5D21AIbED7zzr+aqXmGoPXW8AVMKViZza22dgqb2pq/4DA2i6B1
/nHmDfxM/GziYlbg7bkf3ETstmdJtrTdZbOHwBg/MhikZ0KMhl5pBZKugdT4r3XX
U3Tj+ONTMHiC8ZzWRrvKEE9fRt10/L/Un3VAeyuEDdHr+a5yE0BmaR90j5nlQQhm
hS4PSAYXoo/+0BH7nc+io4SInpL2TwT4QRKoYanTt5LjLhiU35aU/OkQ19oetT/M
RfzZ46cr8eJxBsvrDVBI++3kvUL8rFW3R/JzHZS/6QKBgQD1fjXx+whIxGB8FVwA
LXpqv66dnUTear0a7VQ9y4FTaksNVAUcJoShC++hetmWmX47RR5iKPaxE0rPCBe+
DrQHoQom+Xrzi7MVaQSTQXqwrGmWd4F0erKvaKVfB4YB1vxR+6Q3xY797bTDhcVC
arK+k8fkqExviH/J8VlFu99JowKBgQDSKUBjlnSl+OWh58v3gEBd4YnASaRumX0z
62jvtStT/YyzJA2MyTV5X9ZwdjePi87VGAB1urLFkK5sDHWkKLC1Uj5ndpYqDzVw
eeUSvS32tNpS7NkIA0JDMqlYgq+wU2trHaBme1dSkre6chF6B5fS8SYWQKpLjped
N0J0c4lDxwKBgQDc2F6VQrywIaGe3uQ18LO5BpmChzGmWSWn7KslMEc2kF/WLKiw
K2KTMpavkUHfflQV49cyfSF4KR/aYbBiNP32AwSMDVFzeVBwyVnpUzWZbHFMgFPA
QoUu0Zg7hhwi2ZGB+zw/RAWgIFDGuDe9yRjl4zInXNPuXkB/nhQubJWxuwKBgFDP
a+LfR5tKSYIoD1XsCtQOlVlK999PRcVhD8iccTyqkh+QDWXFOLqjD2HPEy4vJCjs
QcEDORqet3L0l4e33brbFQPTpYomrvXA6UR7WeEzSX/5crqSBjiwkk1mcwfqC7P0
gGjnpHwrzlny4qV5pfeGoo6L7u9+tO3PAc6lXnKhAoGAf8UdZGpwHzZi3d6LWKnI
CF6cPoRAME2qwxMBtItHmQso9vdsIv3TO3xpizm8zY2yXM5zPlorOcX0ldpHxQze
AnThVsu+gJq8hkjwBGjyKKMD7XjKkcFSZ4WyUN+CefBRfGaWQ3/hdRxXiABv3NV7
V04h1T7jJtgq/kDt/xL6D+M=
-----END RSA PRIVATE KEY-----`,
    enc,
    'oaep'
  );
  console.log(
    'crypto.decryptRSA: ',
    dec,
    crypto.base64decode(dec),
    ' elapsed ',
    new Date().getTime() - start + 'ms'
  );
}

export function signRSA() {
  let start = new Date().getTime();
  let sig = crypto.signRSA(
    `-----BEGIN RSA PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDJiRc2MUErUCb5
dfqnfUIToiXjVLCv9aB3bcHqgi9xYy/4lGdNmKMHzpP22Kk46d3bEqOQ/RHX0o3W
uUI6wo1ts3t4vkFk+2x4OgGgQRT8tZO+Cf54xbKRJJv/fU6oJrb0dPvAHwryTVK+
SGGs/8R/eYoTx1G3Ws8EN0pbtl7LO0/W/2zW9E8+RKRVI0CeWeJ5x1orP+Y1PTI1
S+Xytr4JwYFE9O3cwotEI6kDygZyQyQYRgEL0wV0gIS67YmP13xrLu0vjNDojKD6
OSqLPajiJvpDBSnX77O/5ANMPCieDkcsA2s1pLCQcQbp8hj7T0o8ExHQOGiewrne
4c8cEua1AgMBAAECggEAFrmssmGvdZDeNDcHgqdvMgOQvieonM7Xv1/TA/yWGPUU
TbV+SJOznoe+y5D21AIbED7zzr+aqXmGoPXW8AVMKViZza22dgqb2pq/4DA2i6B1
/nHmDfxM/GziYlbg7bkf3ETstmdJtrTdZbOHwBg/MhikZ0KMhl5pBZKugdT4r3XX
U3Tj+ONTMHiC8ZzWRrvKEE9fRt10/L/Un3VAeyuEDdHr+a5yE0BmaR90j5nlQQhm
hS4PSAYXoo/+0BH7nc+io4SInpL2TwT4QRKoYanTt5LjLhiU35aU/OkQ19oetT/M
RfzZ46cr8eJxBsvrDVBI++3kvUL8rFW3R/JzHZS/6QKBgQD1fjXx+whIxGB8FVwA
LXpqv66dnUTear0a7VQ9y4FTaksNVAUcJoShC++hetmWmX47RR5iKPaxE0rPCBe+
DrQHoQom+Xrzi7MVaQSTQXqwrGmWd4F0erKvaKVfB4YB1vxR+6Q3xY797bTDhcVC
arK+k8fkqExviH/J8VlFu99JowKBgQDSKUBjlnSl+OWh58v3gEBd4YnASaRumX0z
62jvtStT/YyzJA2MyTV5X9ZwdjePi87VGAB1urLFkK5sDHWkKLC1Uj5ndpYqDzVw
eeUSvS32tNpS7NkIA0JDMqlYgq+wU2trHaBme1dSkre6chF6B5fS8SYWQKpLjped
N0J0c4lDxwKBgQDc2F6VQrywIaGe3uQ18LO5BpmChzGmWSWn7KslMEc2kF/WLKiw
K2KTMpavkUHfflQV49cyfSF4KR/aYbBiNP32AwSMDVFzeVBwyVnpUzWZbHFMgFPA
QoUu0Zg7hhwi2ZGB+zw/RAWgIFDGuDe9yRjl4zInXNPuXkB/nhQubJWxuwKBgFDP
a+LfR5tKSYIoD1XsCtQOlVlK999PRcVhD8iccTyqkh+QDWXFOLqjD2HPEy4vJCjs
QcEDORqet3L0l4e33brbFQPTpYomrvXA6UR7WeEzSX/5crqSBjiwkk1mcwfqC7P0
gGjnpHwrzlny4qV5pfeGoo6L7u9+tO3PAc6lXnKhAoGAf8UdZGpwHzZi3d6LWKnI
CF6cPoRAME2qwxMBtItHmQso9vdsIv3TO3xpizm8zY2yXM5zPlorOcX0ldpHxQze
AnThVsu+gJq8hkjwBGjyKKMD7XjKkcFSZ4WyUN+CefBRfGaWQ3/hdRxXiABv3NV7
V04h1T7jJtgq/kDt/xL6D+M=
-----END RSA PRIVATE KEY-----`,
    crypto.base64encode('abc'),
    'sha256'
  );
  console.log(
    'crypto.signRSA: ',
    crypto.base64encode('abc'),
    sig,
    ' elapsed ',
    new Date().getTime() - start + 'ms'
  );
  start = new Date().getTime();
  let verify = crypto.verifyRSA(
    `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyYkXNjFBK1Am+XX6p31C
E6Il41Swr/Wgd23B6oIvcWMv+JRnTZijB86T9tipOOnd2xKjkP0R19KN1rlCOsKN
bbN7eL5BZPtseDoBoEEU/LWTvgn+eMWykSSb/31OqCa29HT7wB8K8k1SvkhhrP/E
f3mKE8dRt1rPBDdKW7ZeyztP1v9s1vRPPkSkVSNAnlniecdaKz/mNT0yNUvl8ra+
CcGBRPTt3MKLRCOpA8oGckMkGEYBC9MFdICEuu2Jj9d8ay7tL4zQ6Iyg+jkqiz2o
4ib6QwUp1++zv+QDTDwong5HLANrNaSwkHEG6fIY+09KPBMR0DhonsK53uHPHBLm
tQIDAQAB
-----END PUBLIC KEY-----`,
    crypto.base64encode('abc'),
    sig,
    'sha256'
  );
  console.log(
    'crypto.verifyRSA: ',
    verify,
    'abc',
    ' elapsed ',
    new Date().getTime() - start + 'ms'
  );
}

export function keyWrapUnWrap() {
  let start = new Date().getTime();
  let wrapped = crypto.keyWrapAES(
    crypto.base64encode('5v8y/B?E(H+MbQeThWmZq3t6w9z$C&F)'),
    crypto.base64encode('5v8y/B?E(H+MbQeThWmZq3t6w9z$C&F)')
  );
  console.log(
    'crypto.keyWrapAES:',
    wrapped,
    crypto.keyUnWrapAES(
      crypto.base64encode('5v8y/B?E(H+MbQeThWmZq3t6w9z$C&F)'),
      wrapped
    ),
    ' elapsed',
    new Date().getTime() - start + 'ms'
  );
}

export function encryptAES256GCM() {
  let benchSTR = '';
  const possible =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < 1000000; i++) {
    benchSTR += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  let encodedString = crypto.base64encode(benchSTR);

  let start = new Date().getTime();
  let enc = crypto.encryptAES256GCM(
    crypto.base64encode('5v8y/B?E(H+MbQeThWmZq3t6w9z$C&F)'),
    encodedString,
    crypto.base64encode('aad'),
    crypto.base64encode('5v8y/B?E(H+MbQeThWmZq3t6w9z$C&F)')
  );
  // enc = JSON.parse(
  //   ' {"cipherb":"EyXQdtYmN3U=","atag":"TMriPJGYM+Lev6kTzSJqkA=="}'
  //  );
  crypto.decryptAES256GCM(
    crypto.base64encode('5v8y/B?E(H+MbQeThWmZq3t6w9z$C&F)'),
    enc.cipherb,
    crypto.base64encode('aad'),
    crypto.base64encode('5v8y/B?E(H+MbQeThWmZq3t6w9z$C&F)'),
    enc.atag
  );
  console.log(
    'crypto.encryptAES256GCM: ',
    ' elapsed',
    new Date().getTime() - start + 'ms'
  );
}

export function encryptAEAD() {
  // let benchSTR = '';
  // const possible =
  //   'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  // for (let i = 0; i < 1000000; i++) {
  //   benchSTR += possible.charAt(Math.floor(Math.random() * possible.length));
  // }
  let encodedString = crypto.base64encode('abcd'); //benchSTR);
  let salt = crypto.secureRandomBytes(crypto.secureSymetricAEADnonceLength());
  let key = crypto.secureRandomBytes(crypto.secureSymetricAEADkeyLength());
  let start = new Date().getTime();
  let enc = crypto.encryptSecureSymetricAEAD(
    key,
    encodedString,
    crypto.base64encode('aad'),
    salt
  );
  // enc = JSON.parse(
  //   ' {"cipherb":"EyXQdtYmN3U=","atag":"TMriPJGYM+Lev6kTzSJqkA=="}'
  //  );
  console.log(
    'crypto.encryptAEAD: ',
    encodedString,
    '| secureSymetricAEADkeyLength: ',
    crypto.secureSymetricAEADkeyLength(),
    '| secureSymetricAEADnonceLength: ',
    crypto.secureSymetricAEADnonceLength(),
    '| enc: ',
    JSON.stringify(enc),
    '| result: ',
    crypto.decryptSecureSymetricAEAD(
      key,
      enc.cipherb,
      crypto.base64encode('aad'),
      salt,
      enc.alg
    ),
    ' elapsed',
    new Date().getTime() - start + 'ms'
  );
}

export function encryptAES256GCM_aa() {
  let salt = crypto.base64encode('5v8y/B?E(H+MbQeThWmZq3t6w9z$C&F)');
  let start = new Date().getTime();
  let enc = crypto.encryptAES256GCM(
    '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',
    'Q0VTbWFpbkVuY0NvbnRlbnQ=',
    salt
  );
  //
  let dec = crypto.decryptAES256GCM(
    'kSiQlSoB8k5EkjW9rVdEh3GLHpUtDVdPSMAEBnbBNUI=',
    enc.cipherb,
    'Q0VTbWFpbkVuY0NvbnRlbnQ=',
    salt,
    enc.atag
  );
  dec = crypto.inflate(dec);
  dec = crypto.base64decode(dec);
  console.log(
    'crypto.decryptAEAD:  ',
    '| result:  ',
    dec,
    ' elapsed',
    new Date().getTime() - start + 'ms'
  );
}

export function decryptAEAD_aa() {
  let start = new Date().getTime();
  let enc = crypto.encryptSecureSymetricAEAD(
    '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',
    'Q0VTbWFpbkVuY0NvbnRlbnQ=',
    'zlmXFllt3W8='
  );
  //
  let dec = crypto.decryptSecureSymetricAEAD(
    'kSiQlSoB8k5EkjW9rVdEh3GLHpUtDVdPSMAEBnbBNUI=',
    enc.cipherb,
    'Q0VTbWFpbkVuY0NvbnRlbnQ=',
    'zlmXFllt3W8=',
    'chacha20poly1305'
  );
  dec = crypto.inflate(dec);
  dec = crypto.base64decode(dec);
  console.log(
    'crypto.decryptAEAD:  ',
    '| result:  ',
    dec,
    ' elapsed',
    new Date().getTime() - start + 'ms'
  );
}
