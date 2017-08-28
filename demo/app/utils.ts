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

export const base64ToArrayBuffer = (str: string) => {
  const arr = new Array<number>();
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
    arr.push(n);
    if (u !== 64) {
      arr.push(r);
    }
    if (a !== 64) {
      arr.push(i);
    }
  }
  return new Uint8Array(arr).buffer;
};

export const arrayBufferToBase64 = (ab: ArrayBuffer) => {
  const ui_arr = new Uint8Array(ab);
  let t = '';
  let n, r, i, s, o, u, a;
  let f = 0;
  while (f < ui_arr.length) {
    n = ui_arr[f++];
    r = ui_arr[f++];
    i = ui_arr[f++];
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

const lookup = [];
const revLookup = [];

const code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
for (let i = 0, len = code.length; i < len; ++i) {
  lookup[i] = code[i];
  revLookup[code.charCodeAt(i)] = i;
}

revLookup['-'.charCodeAt(0)] = 62;
revLookup['_'.charCodeAt(0)] = 63;

const placeHoldersCount = (b64: string) => {
  let len = b64.length;
  if (len % 4 > 0) {
    throw new Error('Invalid string. Length must be a multiple of 4');
  }

  // the number of equal signs (place holders)
  // if there are two placeholders, than the two characters before it
  // represent one byte
  // if there is only one, then the three characters before it represent 2 bytes
  // this is just a cheap hack to not do indexOf twice
  return b64[len - 2] === '=' ? 2 : b64[len - 1] === '=' ? 1 : 0;
};

const byteLength = (b64: string) => {
  // base64 is 4/3 + up to two characters of the original data
  return b64.length * 3 / 4 - placeHoldersCount(b64);
};

export const stringToArrayBuffer = (b64: string): ArrayBuffer => {
  let i, l, tmp, placeHolders, arr: Uint8Array;
  let len = b64.length;
  placeHolders = placeHoldersCount(b64);

  arr = new Uint8Array(len * 3 / 4 - placeHolders);

  // if there are placeholders, only get up to the last complete 4 chars
  l = placeHolders > 0 ? len - 4 : len;

  let L = 0;

  for (i = 0; i < l; i += 4) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 18) |
      (revLookup[b64.charCodeAt(i + 1)] << 12) |
      (revLookup[b64.charCodeAt(i + 2)] << 6) |
      revLookup[b64.charCodeAt(i + 3)];
    arr[L++] = (tmp >> 16) & 0xff;
    arr[L++] = (tmp >> 8) & 0xff;
    arr[L++] = tmp & 0xff;
  }

  if (placeHolders === 2) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 2) |
      (revLookup[b64.charCodeAt(i + 1)] >> 4);
    arr[L++] = tmp & 0xff;
  } else if (placeHolders === 1) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 10) |
      (revLookup[b64.charCodeAt(i + 1)] << 4) |
      (revLookup[b64.charCodeAt(i + 2)] >> 2);
    arr[L++] = (tmp >> 8) & 0xff;
    arr[L++] = tmp & 0xff;
  }

  return arr.buffer;
};

const tripletToBase64 = num => {
  return (
    lookup[(num >> 18) & 0x3f] +
    lookup[(num >> 12) & 0x3f] +
    lookup[(num >> 6) & 0x3f] +
    lookup[num & 0x3f]
  );
};

const encodeChunk = (uint8, start, end) => {
  let tmp;
  let output = [];
  for (let i = start; i < end; i += 3) {
    tmp = (uint8[i] << 16) + (uint8[i + 1] << 8) + uint8[i + 2];
    output.push(tripletToBase64(tmp));
  }
  return output.join('');
};

export const arrayBufferToString = (arr: ArrayBuffer): string => {
  let tmp;
  const uint8 = new Uint8Array(arr);
  let len = uint8.length;
  let extraBytes = len % 3; // if we have 1 byte left, pad 2 bytes
  let output = '';
  let parts = [];
  let maxChunkLength = 16383; // must be multiple of 3

  // go through the array every three bytes, we'll deal with trailing stuff later
  for (let i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
    parts.push(
      encodeChunk(
        uint8,
        i,
        i + maxChunkLength > len2 ? len2 : i + maxChunkLength
      )
    );
  }

  // pad the end with zeros, but make sure to not forget the extra bytes
  if (extraBytes === 1) {
    tmp = uint8[len - 1];
    output += lookup[tmp >> 2];
    output += lookup[(tmp << 4) & 0x3f];
    output += '==';
  } else if (extraBytes === 2) {
    tmp = (uint8[len - 2] << 8) + uint8[len - 1];
    output += lookup[tmp >> 10];
    output += lookup[(tmp >> 4) & 0x3f];
    output += lookup[(tmp << 2) & 0x3f];
    output += '=';
  }

  parts.push(output);

  return parts.join('');
};

export const stringToBase64 = (str: string) => asciiToBase64(encodeUTF8(str));

export const base64ToString = (str: string) => decodeUTF8(base64ToASCII(str));

// export const arrayBufferToBase64 = (ab: ArrayBuffer) =>
//   asciiToBase64(arrayBufferToString(ab));

// export const base64ToArrayBuffer = (base64: string) =>
//   stringToArrayBuffer(base64ToASCII(base64));

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

// export const stringToArrayBuffer = (s: string): ArrayBuffer => {
//   let a: Uint8Array = new Uint8Array(s.length);
//   for (let i = 0; i < s.length; i++) {
//     a[i] = s.charCodeAt(i) & 0xff;
//   }
//   return a.buffer;
// };

// export const arrayBufferToString = (a: ArrayBuffer): string => {
//   const array = new Uint8Array(a);
//   let str = '';

//   for (let i = 0; i < array.length; i++) {
//     str += String.fromCharCode(array[i]);
//   }
//   return str;
// };

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

export const arrayBufferToUTF8 = (ab: ArrayBuffer) => {
  const bytes = new Uint8Array(ab);
  var s = '';
  var i = 0;
  while (i < bytes.length) {
    var c = bytes[i++];
    if (c > 127) {
      if (c > 191 && c < 224) {
        if (i >= bytes.length) throw 'UTF-8 decode: incomplete 2-byte sequence';
        c = ((c & 31) << 6) | (bytes[i] & 63);
      } else if (c > 223 && c < 240) {
        if (i + 1 >= bytes.length)
          throw 'UTF-8 decode: incomplete 3-byte sequence';
        c = ((c & 15) << 12) | ((bytes[i] & 63) << 6) | (bytes[++i] & 63);
      } else if (c > 239 && c < 248) {
        if (i + 2 >= bytes.length)
          throw 'UTF-8 decode: incomplete 4-byte sequence';
        c =
          ((c & 7) << 18) |
          ((bytes[i] & 63) << 12) |
          ((bytes[++i] & 63) << 6) |
          (bytes[++i] & 63);
      } else
        throw 'UTF-8 decode: unknown multibyte start 0x' +
          c.toString(16) +
          ' at index ' +
          (i - 1);
      ++i;
    }

    if (c <= 0xffff) s += String.fromCharCode(c);
    else if (c <= 0x10ffff) {
      c -= 0x10000;
      s += String.fromCharCode((c >> 10) | 0xd800);
      s += String.fromCharCode((c & 0x3ff) | 0xdc00);
    } else
      throw 'UTF-8 decode: code point 0x' +
        c.toString(16) +
        ' exceeds UTF-16 reach';
  }
  return s;
};
