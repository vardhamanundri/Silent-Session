#!/usr/bin/env python3
"""
SILENTSESSION offline solver.

Everything the final token (flag) depends on is either:
  (a) obfuscated-but-deterministic constants baked into Keys.java, or
  (b) the APK's own signing certificate (unchanged as long as the
      package is unmodified, as the challenge guarantees).

Neither depends on anything that only exists at runtime on the device
(the AndroidKeyStore wrap/unwrap in CryptoBox is just in-memory
transport for `grant` between step() and fetch() -- it round-trips
to the identical bytes, it never alters them). So the whole chain can
be replayed here, offline, against the unmodified APK's own assets.

Requires: pip install pycryptodome
Usage: python3 solve_offline.py SILENTSESSION.apk
"""
import sys, zipfile, hashlib, hmac, struct, subprocess, tempfile, os
from Crypto.Cipher import AES

# --- constants copied verbatim from the decompiled Keys.java / Protocol.java ---
A1 = "71d59ae7cdd88ef86440e340fbda6d2c"
A2 = "f5d7a3c342afe542e63087093c5c49ac"
GS = "84ae690798cbca013ecb6d5f5788de2cfbf313d48c58383defc46e47f5a7fe90"
P  = ["13d057621df0c005", "323c6c8660bf5d60", "238dbd3a40ae7f80"]
SALT = b"silentsession/seal/v3"
INFO = b"recovery-token"
SEALED_ASSET = "assets/sealed.bin"


def sha256(b): return hashlib.sha256(b).digest()


def mask_bytes(label: str, n: int) -> bytes:
    out = b""
    block = sha256(label.encode("utf-8"))
    while len(out) < n:
        c = min(len(block), n - len(out))
        out += block[:c]
        block = sha256(block)
    return out[:n]


def deob(hexstr: str, label: str) -> bytes:
    obf = bytes.fromhex(hexstr)
    m = mask_bytes(label, len(obf))
    return bytes(a ^ b for a, b in zip(obf, m))


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac_sha256(salt, ikm)
    out, t, counter = b"", b"", 1
    while len(out) < length:
        t = hmac_sha256(prk, t + info + bytes([counter]))
        out += t
        counter += 1
    return out[:length]


def extract_signer_cert_der(apk_path: str) -> bytes:
    """Pull the signer cert's DER bytes out of the v1 JAR signature
    block (META-INF/*.RSA). Works because this APK uses the same
    key/cert across v1/v2/v3 signing (verified by locating the same
    DER bytes inside the APK Signing Block too)."""
    with zipfile.ZipFile(apk_path) as z:
        rsa_name = next(n for n in z.namelist() if n.upper().endswith(".RSA") or n.upper().endswith(".DSA"))
        pkcs7 = z.read(rsa_name)
    with tempfile.TemporaryDirectory() as td:
        pkcs7_path = os.path.join(td, "sig.p7")
        cert_path = os.path.join(td, "cert.pem")
        der_path = os.path.join(td, "cert.der")
        with open(pkcs7_path, "wb") as f:
            f.write(pkcs7)
        subprocess.run(["openssl", "pkcs7", "-inform", "DER", "-in", pkcs7_path,
                         "-print_certs", "-out", cert_path], check=True, capture_output=True)
        subprocess.run(["openssl", "x509", "-in", cert_path, "-outform", "DER",
                         "-out", der_path], check=True, capture_output=True)
        with open(der_path, "rb") as f:
            return f.read()


def main():
    apk_path = sys.argv[1] if len(sys.argv) > 1 else "SILENTSESSION.apk"

    appSecret = deob(A1, "ss/k/a") + deob(A2, "ss/k/b")
    seed = deob(GS, "ss/k/g")
    tokens = [deob(P[i], f"ss/k/p{i}") for i in range(3)]

    print("recovered proof tokens (the 'p' args step() expects):")
    for i, t in enumerate(tokens):
        print(f"  slot {i}: {t.decode('utf-8')!r}")

    cert_der = extract_signer_cert_der(apk_path)
    signer_digest = sha256(cert_der)
    print("signer cert SHA-256:", signer_digest.hex())

    # CryptoBox.grant()
    t = seed
    for i in range(3):
        t = hmac_sha256(t, tokens[i])
    grant = hmac_sha256(t, signer_digest)

    # CryptoBox.deriveSealKey()
    ikm = bytes(appSecret[i] ^ grant[i % len(grant)] for i in range(32))
    seal_key = hkdf(ikm, SALT, INFO, 32)

    with zipfile.ZipFile(apk_path) as z:
        blob = z.read(SEALED_ASSET)
    nonce, ct = blob[:12], blob[12:]
    tag, ciphertext = ct[-16:], ct[:-16]

    cipher = AES.new(seal_key, AES.MODE_GCM, nonce=nonce)
    pt = cipher.decrypt_and_verify(ciphertext, tag)
    print("\nRECOVERY TOKEN:", pt.decode("utf-8"))


if __name__ == "__main__":
    main()
