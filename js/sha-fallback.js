/**
 * Pure-JS SHA-256 and SHA-1 fallback for insecure contexts
 * where crypto.subtle is unavailable.
 *
 * Returns Promise<ArrayBuffer> to match crypto.subtle.digest() API.
 */

const ShaFallback = (() => {

  // SHA-256 initial hash values (first 32 bits of square roots of first 8 primes)
  const H256 = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);

  // SHA-256 round constants (first 32 bits of cube roots of first 64 primes)
  const K256 = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);

  function sha256(data) {
    const msg = data instanceof Uint8Array ? data : new Uint8Array(data);
    const len = msg.length;

    // Pre-processing: pad to 512-bit blocks
    const bitLen = len * 8;
    // message + 0x80 byte + padding zeros + 8-byte length
    const padded = new Uint8Array(Math.ceil((len + 9) / 64) * 64);
    padded.set(msg);
    padded[len] = 0x80;
    // Big-endian 64-bit length at the end
    const dv = new DataView(padded.buffer);
    // JS bitwise ops are 32-bit, so split the bit length
    dv.setUint32(padded.length - 4, bitLen >>> 0);
    if (bitLen > 0xFFFFFFFF) {
      dv.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
    }

    const h = new Uint32Array(H256);
    const w = new Uint32Array(64);

    for (let offset = 0; offset < padded.length; offset += 64) {
      for (let i = 0; i < 16; i++) {
        w[i] = dv.getUint32(offset + i * 4);
      }
      for (let i = 16; i < 64; i++) {
        const s0 = (ror(w[i-15], 7) ^ ror(w[i-15], 18) ^ (w[i-15] >>> 3)) >>> 0;
        const s1 = (ror(w[i-2], 17) ^ ror(w[i-2], 19) ^ (w[i-2] >>> 10)) >>> 0;
        w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
      }

      let a = h[0], b = h[1], c = h[2], d = h[3];
      let e = h[4], f = h[5], g = h[6], hh = h[7];

      for (let i = 0; i < 64; i++) {
        const S1 = (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) >>> 0;
        const ch = ((e & f) ^ (~e & g)) >>> 0;
        const temp1 = (hh + S1 + ch + K256[i] + w[i]) >>> 0;
        const S0 = (ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) >>> 0;
        const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
        const temp2 = (S0 + maj) >>> 0;

        hh = g; g = f; f = e;
        e = (d + temp1) >>> 0;
        d = c; c = b; b = a;
        a = (temp1 + temp2) >>> 0;
      }

      h[0] = (h[0] + a) >>> 0;
      h[1] = (h[1] + b) >>> 0;
      h[2] = (h[2] + c) >>> 0;
      h[3] = (h[3] + d) >>> 0;
      h[4] = (h[4] + e) >>> 0;
      h[5] = (h[5] + f) >>> 0;
      h[6] = (h[6] + g) >>> 0;
      h[7] = (h[7] + hh) >>> 0;
    }

    const result = new ArrayBuffer(32);
    const out = new DataView(result);
    for (let i = 0; i < 8; i++) out.setUint32(i * 4, h[i]);
    return Promise.resolve(result);
  }

  // SHA-1 initial hash values
  const H1 = new Uint32Array([
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
  ]);

  function sha1(data) {
    const msg = data instanceof Uint8Array ? data : new Uint8Array(data);
    const len = msg.length;
    const bitLen = len * 8;
    const padded = new Uint8Array(Math.ceil((len + 9) / 64) * 64);
    padded.set(msg);
    padded[len] = 0x80;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 4, bitLen >>> 0);
    if (bitLen > 0xFFFFFFFF) {
      dv.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
    }

    const h = new Uint32Array(H1);
    const w = new Uint32Array(80);

    for (let offset = 0; offset < padded.length; offset += 64) {
      for (let i = 0; i < 16; i++) {
        w[i] = dv.getUint32(offset + i * 4);
      }
      for (let i = 16; i < 80; i++) {
        w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
      }

      let a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];

      for (let i = 0; i < 80; i++) {
        let f, k;
        if (i < 20) {
          f = ((b & c) ^ (~b & d)) >>> 0;
          k = 0x5A827999;
        } else if (i < 40) {
          f = (b ^ c ^ d) >>> 0;
          k = 0x6ED9EBA1;
        } else if (i < 60) {
          f = ((b & c) ^ (b & d) ^ (c & d)) >>> 0;
          k = 0x8F1BBCDC;
        } else {
          f = (b ^ c ^ d) >>> 0;
          k = 0xCA62C1D6;
        }
        const temp = (rol(a, 5) + f + e + k + w[i]) >>> 0;
        e = d; d = c;
        c = rol(b, 30);
        b = a; a = temp;
      }

      h[0] = (h[0] + a) >>> 0;
      h[1] = (h[1] + b) >>> 0;
      h[2] = (h[2] + c) >>> 0;
      h[3] = (h[3] + d) >>> 0;
      h[4] = (h[4] + e) >>> 0;
    }

    const result = new ArrayBuffer(20);
    const out = new DataView(result);
    for (let i = 0; i < 5; i++) out.setUint32(i * 4, h[i]);
    return Promise.resolve(result);
  }

  function ror(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }
  function rol(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }

  return { sha256, sha1 };
})();
