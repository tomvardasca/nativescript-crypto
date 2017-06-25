import * as observable from 'tns-core-modules/data/observable';
import * as pages from 'tns-core-modules/ui/page';

import { HelloWorldModel } from './main-view-model';
import { NSCrypto } from 'nativescript-crypto';

let helloWorldModel: HelloWorldModel;
// Event handler for Page 'loaded' event attached in main-page.xml
export function pageLoaded(args: observable.EventData) {
  // Get the event sender
  let page = <pages.Page>args.object;
  helloWorldModel = new HelloWorldModel();
  page.bindingContext = helloWorldModel;
}

const crypto = new NSCrypto();

export function sha256() {
  let start = new Date().getTime();
  console.log(
    'crypto.hash 256: ',
    crypto.hash('abc', 'sha256'),
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
    `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyYkXNjFBK1Am+XX6p31C
E6Il41Swr/Wgd23B6oIvcWMv+JRnTZijB86T9tipOOnd2xKjkP0R19KN1rlCOsKN
bbN7eL5BZPtseDoBoEEU/LWTvgn+eMWykSSb/31OqCa29HT7wB8K8k1SvkhhrP/E
f3mKE8dRt1rPBDdKW7ZeyztP1v9s1vRPPkSkVSNAnlniecdaKz/mNT0yNUvl8ra+
CcGBRPTt3MKLRCOpA8oGckMkGEYBC9MFdICEuu2Jj9d8ay7tL4zQ6Iyg+jkqiz2o
4ib6QwUp1++zv+QDTDwong5HLANrNaSwkHEG6fIY+09KPBMR0DhonsK53uHPHBLm
tQIDAQAB
-----END PUBLIC KEY-----`,
    'gSpGS+z6HtMeQ/CUJFHL6Wwx6OLNRyXvtBS0x8GXs7VNCMq2xc26ovO2Pj+5pOdGQ8PiT6ppbd8XB9wiFya5Mg==',
    'oaep'
  );
  console.log(
    'crypto.encryptRSA: ',
    'gSpGS+z6HtMeQ/CUJFHL6Wwx6OLNRyXvtBS0x8GXs7VNCMq2xc26ovO2Pj+5pOdGQ8PiT6ppbd8XB9wiFya5Mg==',
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
    crypto.base64encode('eyJhbGciOiJSUzI1NiIsImN0eSI6Impzb24ifQ.ImFiYyI'),
    'sha256'
  );
  console.log(
    'crypto.signRSA: ',
    crypto.base64encode('eyJhbGciOiJSUzI1NiIsImN0eSI6Impzb24ifQ.ImFiYyI'),
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
