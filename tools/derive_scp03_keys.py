#!/usr/bin/env python3
"""
Derive per-device SCP03 static keys from a master key and SE UID,
and compute the KCV and DEK-encrypted form used in the GP PUT KEY command.

KDF matches se05x::deriveScp03Keys() in cpp_app/se05x_provision.cpp:
  K_i = AES-CMAC(master_key, i || uid)
  i = 0x01 → ENC,  0x02 → MAC,  0x03 → DEK

KCV matches aesKcv() in cpp_app/se05x_provision.cpp:
  KCV_i = AES-ECB(K_i, 0x01 * 16)[0:3]

DEK-wrap matches aesDekEncrypt() in cpp_app/se05x_provision.cpp:
  enc_K_i = AES-ECB(current_DEK, K_i)

Usage:
  python3 derive_scp03_keys.py --master-key <hex32> --uid <hex36> [--current-dek <hex32>] [--out <file>]

  --current-dek  16-byte current static DEK (needed to show DEK-encrypted key values
                 that will appear in the PUT KEY APDU body).
                 Default: NXP test DEK abcdabcdabcdabcdabcdabcdabcd0003

Requires: pip install cryptography
"""

import argparse
import sys
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Default NXP test DEK (used when no --current-dek is given and device has factory keys)
DEFAULT_DEK = bytes([
    0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD,
    0xAB, 0xCD, 0xAB, 0xCD, 0xAB, 0xCD, 0x00, 0x03,
])


def aes_cmac(key: bytes, msg: bytes) -> bytes:
    c = CMAC(algorithms.AES(key))
    c.update(msg)
    return c.finalize()


def aes_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    """Single-block AES-128-ECB encrypt."""
    c = Cipher(algorithms.AES(key), modes.ECB())
    enc = c.encryptor()
    return enc.update(block) + enc.finalize()


def kcv(key: bytes) -> bytes:
    """KCV = AES-ECB(key, 0x01 * 16)[0:3]  — matches aesKcv() in se05x_provision.cpp."""
    return aes_ecb_encrypt(key, b'\x01' * 16)[:3]


def dek_wrap(dek: bytes, key: bytes) -> bytes:
    """DEK-encrypt a key: AES-ECB(DEK, key)  — matches aesDekEncrypt()."""
    return aes_ecb_encrypt(dek, key)


def derive_scp03_keys(master_key: bytes, uid: bytes) -> dict:
    if len(master_key) != 16:
        raise ValueError(f"master key must be 16 bytes, got {len(master_key)}")
    if len(uid) != 18:
        raise ValueError(f"UID must be 18 bytes, got {len(uid)}")
    return {
        "ENC": aes_cmac(master_key, bytes([0x01]) + uid),
        "MAC": aes_cmac(master_key, bytes([0x02]) + uid),
        "DEK": aes_cmac(master_key, bytes([0x03]) + uid),
    }


def parse_hex(s: str, name: str) -> bytes:
    s = s.strip().replace(" ", "").replace(":", "")
    if len(s) % 2:
        raise ValueError(f"{name}: odd number of hex digits")
    try:
        return bytes.fromhex(s)
    except ValueError:
        raise ValueError(f"{name}: invalid hex string")


def main():
    parser = argparse.ArgumentParser(
        description="Derive SE05x per-device SCP03 keys and compute KCV / DEK-wrapped forms"
    )
    parser.add_argument(
        "--master-key", required=True, metavar="HEX32",
        help="16-byte AES master key as 32 hex chars",
    )
    parser.add_argument(
        "--uid", required=True, metavar="HEX36",
        help="18-byte SE chip UID as 36 hex chars (from: se05x_crypto_app se uid)",
    )
    parser.add_argument(
        "--current-dek", metavar="HEX32", default=None,
        help="Current 16-byte static DEK as 32 hex chars (used for DEK-wrapped key output). "
             "Defaults to NXP factory DEK abcdabcdabcdabcdabcdabcdabcd0003",
    )
    parser.add_argument(
        "--out", metavar="FILE",
        help="Write SCP03 key file (ENC/MAC/DEK lines) to FILE instead of stdout",
    )
    args = parser.parse_args()

    master_key = parse_hex(args.master_key, "--master-key")
    uid        = parse_hex(args.uid,        "--uid")

    if len(master_key) != 16:
        parser.error(f"--master-key must be 32 hex chars (16 bytes), got {len(master_key)*2}")
    if len(uid) != 18:
        parser.error(f"--uid must be 36 hex chars (18 bytes), got {len(uid)*2}")

    current_dek = DEFAULT_DEK
    if args.current_dek is not None:
        current_dek = parse_hex(args.current_dek, "--current-dek")
        if len(current_dek) != 16:
            parser.error("--current-dek must be 32 hex chars (16 bytes)")

    keys = derive_scp03_keys(master_key, uid)

    # Key file content (written to --out or stdout for SCP03 file update)
    key_file_lines = "\n".join(f"{k} {v.hex()}" for k, v in keys.items()) + "\n"

    if args.out:
        with open(args.out, "w") as f:
            f.write(key_file_lines)
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(key_file_lines)

    # Diagnostic table to stderr: plaintext, KCV, and DEK-wrapped form
    print(file=sys.stderr)
    print("--- diagnostic (matches PUT KEY APDU) ---", file=sys.stderr)
    print(f"  current DEK : {current_dek.hex()}", file=sys.stderr)
    print(file=sys.stderr)
    for name, key in keys.items():
        k = kcv(key)
        w = dek_wrap(current_dek, key)
        print(f"  {name} plaintext : {key.hex()}", file=sys.stderr)
        print(f"  {name} KCV[0:3]  : {k.hex()}  (AES-ECB(key, 0x01×16)[0:3])", file=sys.stderr)
        print(f"  {name} DEK-wrap  : {w.hex()}  (AES-ECB(DEK, key))", file=sys.stderr)
        print(file=sys.stderr)


if __name__ == "__main__":
    main()
