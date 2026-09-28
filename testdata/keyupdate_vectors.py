#!/usr/bin/env python3
# Generates TestKeysUpdate vectors in keys_test.go.
#
# Independent of the Go code: HKDF-Expand-Label is written here over hmac,
# AEAD is OpenSSL through the cryptography package (pip install cryptography).
#
# Output: suite secret0 record0 secret1 record1
# record0 is sealed under secret0 at seq 3, record1 under secret1 = update(secret0) at seq 0.

import hmac, hashlib, struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

def expand(h, prk, info, l):
    out, t, i = b'', b'', 1
    while len(out) < l:
        t = hmac.new(prk, t + info + bytes([i]), h).digest()
        out += t; i += 1
    return out[:l]

def label(h, secret, lbl, ctx, l):
    full = b'tls13 ' + lbl
    info = struct.pack('>H', l) + bytes([len(full)]) + full + bytes([len(ctx)]) + ctx
    return expand(h, secret, info, l)

def seal(suite, key, iv, seq, tp, content):
    inner = content + bytes([tp])
    l = len(inner) + 16
    hdr = bytes([0x17, 3, 3]) + struct.pack('>H', l)
    nonce = bytes(a ^ b for a, b in zip(iv, b'\0'*4 + struct.pack('>Q', seq)))
    a = ChaCha20Poly1305(key) if suite == 0x1303 else AESGCM(key)
    return hdr + a.encrypt(nonce, inner, hdr)

suites = {
    0x1301: (hashlib.sha256, 16, bytes.fromhex('9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5')),  # RFC8448 client app secret
    0x1302: (hashlib.sha384, 32, bytes(range(1, 49))),
    0x1303: (hashlib.sha256, 32, bytes(range(0x40, 0x60))),
}
content = b'key update test'
for suite, (h, kl, s0) in suites.items():
    k0, iv0 = label(h, s0, b'key', b'', kl), label(h, s0, b'iv', b'', 12)
    s1 = label(h, s0, b'traffic upd', b'', len(s0))
    k1, iv1 = label(h, s1, b'key', b'', kl), label(h, s1, b'iv', b'', 12)
    print('%04x' % suite, s0.hex(), seal(suite, k0, iv0, 3, 0x17, content).hex(), s1.hex(), seal(suite, k1, iv1, 0, 0x17, content).hex())
