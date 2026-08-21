#!/usr/bin/env python3
# Reference oracle for BIP38 no-EC-multiply passphrase cracking (rxe38).
# Validated against all four BIP38 spec test vectors. This is the DIFFERENTIAL
# GROUND TRUTH: every C component of rxe38 must reproduce these bytes exactly.
#   pipeline: base58check-decode 6P... -> scrypt(pw, salt=addrhash, 16384,8,8,64)
#             -> dh1||dh2 -> AES256-ECB-decrypt(enc1,enc2, key=dh2) -> XOR dh1
#             -> privkey -> secp256k1 pubkey (compressed per flag 0x20)
#             -> hash160 -> base58 address -> SHA256d[:4] == addrhash ?
# Deps here (dev box): hashlib.scrypt (openssl), cryptography (AES), ecdsa, base58.
import hashlib, base58, ecdsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def ripemd160(b):
    h = hashlib.new('ripemd160'); h.update(b); return h.digest()
def aes256_dec_block(key, block):            # ECB, one 16-byte block, no padding
    c = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return c.update(block) + c.finalize()
def pubkey(priv, compressed):
    p = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1).get_verifying_key().pubkey.point
    x, y = p.x(), p.y()
    return (bytes([2 + (y & 1)]) + x.to_bytes(32,'big')) if compressed \
           else (b'\x04' + x.to_bytes(32,'big') + y.to_bytes(32,'big'))
def address(priv, compressed):
    h160 = ripemd160(hashlib.sha256(pubkey(priv, compressed)).digest())
    return base58.b58encode(b'\x00' + h160 + sha256d(b'\x00'+h160)[:4]).decode()
def wif(priv, compressed):
    payload = b'\x80' + priv + (b'\x01' if compressed else b'')
    return base58.b58encode(payload + sha256d(payload)[:4]).decode()

def bip38_decrypt(enc, passphrase):
    raw = base58.b58decode_check(enc)                       # 39 bytes, checksum stripped
    assert raw[0:2] == b'\x01\x42', "not a no-EC-multiply BIP38 key (prefix != 0x0142)"
    flag = raw[2]; addrhash = raw[3:7]; e1 = raw[7:23]; e2 = raw[23:39]
    compressed = bool(flag & 0x20)
    d = hashlib.scrypt(passphrase.encode('utf-8'), salt=addrhash, n=16384, r=8, p=8,
                       dklen=64, maxmem=64*1024*1024)
    dh1, dh2 = d[:32], d[32:]
    x16 = lambda a,b: bytes(i^j for i,j in zip(a,b))
    priv = x16(aes256_dec_block(dh2, e1), dh1[:16]) + x16(aes256_dec_block(dh2, e2), dh1[16:])
    ok = sha256d(address(priv, compressed).encode('ascii'))[:4] == addrhash
    return priv, compressed, ok, addrhash.hex()

# BIP38 spec test vectors (no EC multiply): (passphrase, encrypted 6P..., expected WIF, compressed)
VECTORS = [
    ("TestingOneTwoThree", "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg", "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR", False),
    ("Satoshi",            "6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq", "5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5", False),
    ("TestingOneTwoThree", "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo", "L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP", True),
    ("Satoshi",            "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7", "KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7", True),
]
if __name__ == "__main__":
    allok = True
    for pw, enc, ewif, ecomp in VECTORS:
        priv, comp, ok, ah = bip38_decrypt(enc, pw)
        w = wif(priv, comp); good = ok and w == ewif and comp == ecomp
        allok &= good
        print(f"[{'PASS' if good else 'FAIL'}] {pw!r:22} comp={comp} addrhash={ah} ok={ok} wif={w}")
    print("ALL 4 SPEC VECTORS PASS" if allok else "FAILED")
