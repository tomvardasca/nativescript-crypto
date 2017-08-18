const base64map =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
const base64pad = '=';
const BI_RM = '0123456789abcdefghijklmnopqrstuvwxyz';

export const intTochar = n => {
  return BI_RM.charAt(n);
};

export const encodeUTF8 = (s: string) => {
  s = s.replace(/rn/g, 'n');
  let t = '';
  for (let n = 0; n < s.length; n++) {
    let r = s.charCodeAt(n);
    if (r < 128) {
      t += String.fromCharCode(r);
    } else if (r > 127 && r < 2048) {
      t += String.fromCharCode((r >> 6) | 192);
      t += String.fromCharCode((r & 63) | 128);
    } else {
      t += String.fromCharCode((r >> 12) | 224);
      t += String.fromCharCode(((r >> 6) & 63) | 128);
      t += String.fromCharCode((r & 63) | 128);
    }
  }
  return t;
};

export const decodeUTF8 = (s: string) => {
  let t = '';
  let n = 0;
  let c1, c2, c3;
  let r = (c1 = c2 = 0);
  while (n < s.length) {
    r = s.charCodeAt(n);
    if (r < 128) {
      t += String.fromCharCode(r);
      n++;
    } else if (r > 191 && r < 224) {
      c2 = s.charCodeAt(n + 1);
      t += String.fromCharCode(((r & 31) << 6) | (c2 & 63));
      n += 2;
    } else {
      c2 = s.charCodeAt(n + 1);
      c3 = s.charCodeAt(n + 2);
      t += String.fromCharCode(((r & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
      n += 3;
    }
  }
  return t;
};

export const asciiToBase64 = (str: string) => {
  let t = '';
  let n, r, i, s, o, u, a;
  let f = 0;
  //  str = encodeUTF8(str);
  while (f < str.length) {
    n = str.charCodeAt(f++);
    r = str.charCodeAt(f++);
    i = str.charCodeAt(f++);
    s = n >> 2;
    o = ((n & 3) << 4) | (r >> 4);
    u = ((r & 15) << 2) | (i >> 6);
    a = i & 63;
    if (isNaN(r)) {
      u = a = 64;
    } else if (isNaN(i)) {
      a = 64;
    }
    t =
      t +
      base64map.charAt(s) +
      base64map.charAt(o) +
      base64map.charAt(u) +
      base64map.charAt(a);
  }
  return t;
};

export const base64ToASCII = (str: string) => {
  let t = '';
  let n, r, i;
  let s, o, u, a;
  let f = 0;
  str = str.replace(/[^A-Za-z0-9+/=]/g, '');
  while (f < str.length) {
    s = base64map.indexOf(str.charAt(f++));
    o = base64map.indexOf(str.charAt(f++));
    u = base64map.indexOf(str.charAt(f++));
    a = base64map.indexOf(str.charAt(f++));
    n = (s << 2) | (o >> 4);
    r = ((o & 15) << 4) | (u >> 2);
    i = ((u & 3) << 6) | a;
    t = t + String.fromCharCode(n);
    if (u !== 64) {
      t = t + String.fromCharCode(r);
    }
    if (a !== 64) {
      t = t + String.fromCharCode(i);
    }
  }
  // t = decodeUTF8(t);
  return t;
};

export const stringToBase64 = (str: string) => asciiToBase64(encodeUTF8(str));

export const base64ToString = (str: string) => decodeUTF8(base64ToASCII(str));

// Use a lookup table to find the index.
const lookup = {
  '0': 0,
  '1': 0,
  '2': 0,
  '3': 0,
  '4': 0,
  '5': 0,
  '6': 0,
  '7': 0,
  '8': 0,
  '9': 0,
  '10': 0,
  '11': 0,
  '12': 0,
  '13': 0,
  '14': 0,
  '15': 0,
  '16': 0,
  '17': 0,
  '18': 0,
  '19': 0,
  '20': 0,
  '21': 0,
  '22': 0,
  '23': 0,
  '24': 0,
  '25': 0,
  '26': 0,
  '27': 0,
  '28': 0,
  '29': 0,
  '30': 0,
  '31': 0,
  '32': 0,
  '33': 0,
  '34': 0,
  '35': 0,
  '36': 0,
  '37': 0,
  '38': 0,
  '39': 0,
  '40': 0,
  '41': 0,
  '42': 0,
  '43': 62,
  '44': 0,
  '45': 0,
  '46': 0,
  '47': 63,
  '48': 52,
  '49': 53,
  '50': 54,
  '51': 55,
  '52': 56,
  '53': 57,
  '54': 58,
  '55': 59,
  '56': 60,
  '57': 61,
  '58': 0,
  '59': 0,
  '60': 0,
  '61': 0,
  '62': 0,
  '63': 0,
  '64': 0,
  '65': 0,
  '66': 1,
  '67': 2,
  '68': 3,
  '69': 4,
  '70': 5,
  '71': 6,
  '72': 7,
  '73': 8,
  '74': 9,
  '75': 10,
  '76': 11,
  '77': 12,
  '78': 13,
  '79': 14,
  '80': 15,
  '81': 16,
  '82': 17,
  '83': 18,
  '84': 19,
  '85': 20,
  '86': 21,
  '87': 22,
  '88': 23,
  '89': 24,
  '90': 25,
  '91': 0,
  '92': 0,
  '93': 0,
  '94': 0,
  '95': 0,
  '96': 0,
  '97': 26,
  '98': 27,
  '99': 28,
  '100': 29,
  '101': 30,
  '102': 31,
  '103': 32,
  '104': 33,
  '105': 34,
  '106': 35,
  '107': 36,
  '108': 37,
  '109': 38,
  '110': 39,
  '111': 40,
  '112': 41,
  '113': 42,
  '114': 43,
  '115': 44,
  '116': 45,
  '117': 46,
  '118': 47,
  '119': 48,
  '120': 49,
  '121': 50,
  '122': 51,
  '123': 0,
  '124': 0,
  '125': 0,
  '126': 0,
  '127': 0,
  '128': 0,
  '129': 0,
  '130': 0,
  '131': 0,
  '132': 0,
  '133': 0,
  '134': 0,
  '135': 0,
  '136': 0,
  '137': 0,
  '138': 0,
  '139': 0,
  '140': 0,
  '141': 0,
  '142': 0,
  '143': 0,
  '144': 0,
  '145': 0,
  '146': 0,
  '147': 0,
  '148': 0,
  '149': 0,
  '150': 0,
  '151': 0,
  '152': 0,
  '153': 0,
  '154': 0,
  '155': 0,
  '156': 0,
  '157': 0,
  '158': 0,
  '159': 0,
  '160': 0,
  '161': 0,
  '162': 0,
  '163': 0,
  '164': 0,
  '165': 0,
  '166': 0,
  '167': 0,
  '168': 0,
  '169': 0,
  '170': 0,
  '171': 0,
  '172': 0,
  '173': 0,
  '174': 0,
  '175': 0,
  '176': 0,
  '177': 0,
  '178': 0,
  '179': 0,
  '180': 0,
  '181': 0,
  '182': 0,
  '183': 0,
  '184': 0,
  '185': 0,
  '186': 0,
  '187': 0,
  '188': 0,
  '189': 0,
  '190': 0,
  '191': 0,
  '192': 0,
  '193': 0,
  '194': 0,
  '195': 0,
  '196': 0,
  '197': 0,
  '198': 0,
  '199': 0,
  '200': 0,
  '201': 0,
  '202': 0,
  '203': 0,
  '204': 0,
  '205': 0,
  '206': 0,
  '207': 0,
  '208': 0,
  '209': 0,
  '210': 0,
  '211': 0,
  '212': 0,
  '213': 0,
  '214': 0,
  '215': 0,
  '216': 0,
  '217': 0,
  '218': 0,
  '219': 0,
  '220': 0,
  '221': 0,
  '222': 0,
  '223': 0,
  '224': 0,
  '225': 0,
  '226': 0,
  '227': 0,
  '228': 0,
  '229': 0,
  '230': 0,
  '231': 0,
  '232': 0,
  '233': 0,
  '234': 0,
  '235': 0,
  '236': 0,
  '237': 0,
  '238': 0,
  '239': 0,
  '240': 0,
  '241': 0,
  '242': 0,
  '243': 0,
  '244': 0,
  '245': 0,
  '246': 0,
  '247': 0,
  '248': 0,
  '249': 0,
  '250': 0,
  '251': 0,
  '252': 0,
  '253': 0,
  '254': 0,
  '255': 0
};

export const arrayBufferToBase64 = (ab: ArrayBuffer) => {
  let bytes = new Uint8Array(ab),
    i,
    len = bytes.length,
    base64 = '';

  for (i = 0; i < len; i += 3) {
    base64 += base64map[bytes[i] >> 2];
    base64 += base64map[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
    base64 += base64map[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
    base64 += base64map[bytes[i + 2] & 63];
  }

  if (len % 3 === 2) {
    base64 = base64.substring(0, base64.length - 1) + '=';
  } else if (len % 3 === 1) {
    base64 = base64.substring(0, base64.length - 2) + '==';
  }

  return base64;
};

export const base64ToArrayBuffer = (base64: string) => {
  let bufferLength = base64.length * 0.75,
    len = base64.length,
    i,
    p = 0,
    encoded1,
    encoded2,
    encoded3,
    encoded4;

  if (base64[base64.length - 1] === '=') {
    bufferLength--;
    if (base64[base64.length - 2] === '=') {
      bufferLength--;
    }
  }

  let arraybuffer = new ArrayBuffer(bufferLength),
    bytes = new Uint8Array(arraybuffer);

  for (i = 0; i < len; i += 4) {
    encoded1 = lookup[base64.charCodeAt(i)];
    encoded2 = lookup[base64.charCodeAt(i + 1)];
    encoded3 = lookup[base64.charCodeAt(i + 2)];
    encoded4 = lookup[base64.charCodeAt(i + 3)];

    bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
    bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
    bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
  }

  return arraybuffer;
};

export const hexToBase64 = h => {
  let i;
  let c;
  let ret = '';
  for (i = 0; i + 3 <= h.length; i += 3) {
    c = parseInt(h.substring(i, i + 3), 16);
    ret += base64map.charAt(c >> 6) + base64map.charAt(c & 63);
  }
  if (i + 1 === h.length) {
    c = parseInt(h.substring(i, i + 1), 16);
    ret += base64map.charAt(c << 2);
  } else if (i + 2 === h.length) {
    c = parseInt(h.substring(i, i + 2), 16);
    ret += base64map.charAt(c >> 2) + base64map.charAt((c & 3) << 4);
  }
  if (base64pad) {
    while ((ret.length & 3) > 0) {
      ret += base64pad;
    }
  }
  return ret;
};

// convert a base64 string to hex
export const base64ToHex = s => {
  let ret = '';
  let i;
  let k = 0; // b64 state, 0-3
  let slop;
  let v;
  for (i = 0; i < s.length; ++i) {
    if (s.charAt(i) === base64pad) {
      break;
    }
    v = base64map.indexOf(s.charAt(i));
    if (v < 0) {
      continue;
    }
    if (k === 0) {
      ret += intTochar(v >> 2);
      slop = v & 3;
      k = 1;
    } else if (k === 1) {
      ret += intTochar((slop << 2) | (v >> 4));
      slop = v & 0xf;
      k = 2;
    } else if (k === 2) {
      ret += intTochar(slop);
      ret += intTochar(v >> 2);
      slop = v & 3;
      k = 3;
    } else {
      ret += intTochar((slop << 2) | (v >> 4));
      ret += intTochar(v & 0xf);
      k = 0;
    }
  }
  if (k === 1) {
    ret += intTochar(slop << 2);
  }
  return ret;
};

// convert a base64 string to a byte/number array
export const base64ToByteArray = s => {
  // piggyback on b64tohex for now, optimize later
  let h = base64ToHex(s);
  let a = new Array();
  for (let i = 0; 2 * i < h.length; ++i) {
    a[i] = parseInt(h.substring(2 * i, 2 * i + 2), 16);
  }
  return a;
};

export const hexToUint8Array = (hex: string) => {
  let out = new Uint8Array(Math.ceil(hex.length / 2));
  let i = 0,
    j = 0;
  if (hex.length & 1) {
    // odd number of characters, convert first character alone
    i = 1;
    out[j++] = parseInt(hex[0], 16);
  }
  // convert 2 characters (1 byte) at a time
  for (; i < hex.length; i += 2) {
    out[j++] = parseInt(hex.substr(i, 2), 16);
  }
  return out;
};

export const isBase64 = s => {
  s = s.replace(/\s+/g, '');
  if (s.match(/^[0-9A-Za-z+\/]+={0,3}$/) && s.length % 4 === 0) {
    return true;
  } else {
    return false;
  }
};

export const isBase64URL = s => {
  if (s.match(/[+/=]/)) {
    return false;
  }
  s = base64URLtoBase64(s);
  return isBase64(s);
};

export const base64toBase64url = s => {
  s = s.replace(/\=/g, '');
  s = s.replace(/\+/g, '-');
  s = s.replace(/\//g, '_');
  return s;
};

export const base64URLtoBase64 = s => {
  if (s.length % 4 === 2) {
    s = s + '==';
  } else if (s.length % 4 === 3) {
    s = s + '=';
  }
  s = s.replace(/-/g, '+');
  s = s.replace(/_/g, '/');
  return s;
};

export const base64uToHex = s => base64ToHex(base64URLtoBase64(s));
export const hexToBase64u = s => base64toBase64url(hexToBase64(s));

export const base64uToString = s => base64ToString(base64URLtoBase64(s));
export const stringToBase64u = s => base64toBase64url(stringToBase64(s));

export const base64uToArrayBuffer = s =>
  base64ToArrayBuffer(base64URLtoBase64(s));

export const arrayBufferToBase64u = s =>
  base64toBase64url(arrayBufferToBase64(s));

export const hexTobase64WithNL = s => {
  const b64 = hexToBase64(s);
  let b64nl = b64.replace(/(.{64})/g, '$1\r\n');
  b64nl = b64nl.replace(/\r\n$/, '');
  return b64nl;
};

export const hexToPEM = (dataHex, pemHeader) => {
  const pemBody = hexTobase64WithNL(dataHex);
  return (
    '-----BEGIN ' +
    pemHeader +
    '-----\r\n' +
    pemBody +
    '\r\n-----END ' +
    pemHeader +
    '-----\r\n'
  );
};

export const stringToArray = (s: string) => {
  let a: number[] = new Array<number>();
  for (let i = 0; i < s.length; i++) {
    a[i] = s.charCodeAt(i);
  }
  return a;
};

export const stringToArrayBuffer = (s: string): ArrayBuffer => {
  let a: Uint8Array = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    a[i] = s.charCodeAt(i) & 0xff;
  }
  return a.buffer;
};

export const arrayBufferToString = (a: ArrayBuffer): string => {
  const array = new Uint8Array(a);
  let str = '';

  for (let i = 0; i < array.length; i++) {
    str += String.fromCharCode(array[i]);
  }
  return str;
};

export const arrayToHex = (a: number[]) => {
  let s = '';
  for (let i = 0; i < a.length; i++) {
    let hex1 = a[i].toString(16);
    if (hex1.length === 1) {
      hex1 = '0' + hex1;
    }
    s = s + hex1;
  }
  return s;
};

export const stringToHex = (s: string) => arrayToHex(stringToArray(s));
