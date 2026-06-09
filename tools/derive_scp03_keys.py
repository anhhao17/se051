#!/usr/bin/env python3
"""
Derive per-device SCP03 static keys from a master key + SE UID, and (optionally)
drive the on-device rotation end to end.

KDF (this tool is the single source of truth for derivation; the C++ CLI takes
the resulting ENC/MAC/DEK as explicit arguments and does the DEK-wrapping/KCV
itself inside `se rotate-scp03`):

    K_i = AES-CMAC(master_key, i || uid)
    i = 0x01 -> ENC, 0x02 -> MAC, 0x03 -> DEK

Modes
-----
1. Derive only (default): print or --out a key file (ENC/MAC/DEK lines).
       derive_scp03_keys.py --master-key <hex32> --uid <hex36> [--out FILE]

2. Auto UID: read the UID from the device instead of passing --uid.
       derive_scp03_keys.py --master-key <hex32> --app ./se05x_crypto_app

3. Rotate: derive, then run the device rotation with --confirm.  The CLI wraps
   the new keys with the *current* DEK and, on success, writes the new keys to
   $EX_SSS_BOOT_SCP03_PATH (or --key-out), backing the old file up to .bak.
       derive_scp03_keys.py --master-key <hex32> --app ./se05x_crypto_app --rotate

Requires: pip install cryptography
"""

import argparse
import os
import subprocess
import sys

from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ---------- crypto primitives ----------

def aes_cmac(key: bytes, msg: bytes) -> bytes:
    c = CMAC(algorithms.AES(key))
    c.update(msg)
    return c.finalize()


def aes_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    """Single-block AES-128-ECB encrypt."""
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def kcv(key: bytes) -> bytes:
    """GP key check value: AES-ECB(key, 0x01*16)[0:3] (what the SE recomputes)."""
    return aes_ecb_encrypt(key, b"\x01" * 16)[:3]


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


# ---------- helpers ----------

def parse_hex(s: str, name: str) -> bytes:
    s = s.strip().replace(" ", "").replace(":", "")
    if len(s) % 2:
        raise ValueError(f"{name}: odd number of hex digits")
    try:
        return bytes.fromhex(s)
    except ValueError:
        raise ValueError(f"{name}: invalid hex string")


def key_file_text(keys: dict) -> str:
    return "".join(f"{k} {v.hex()}\n" for k, v in keys.items())


def read_uid_from_device(app: str, extra: list) -> bytes:
    """Run `<app> se uid` and parse the 36-hex-char UID from its output."""
    cmd = [app] + extra + ["se", "uid"]
    print(f"+ {' '.join(cmd)}", file=sys.stderr)
    out = subprocess.run(cmd, capture_output=True, text=True)
    blob = out.stdout + out.stderr
    # UID line looks like: "UID (18 bytes): 04005001....2390"
    for tok in blob.replace(":", " ").split():
        t = tok.strip()
        if len(t) == 36 and all(c in "0123456789abcdefABCDEF" for c in t):
            return bytes.fromhex(t)
    raise RuntimeError(
        "could not parse an 18-byte UID from `se uid` output:\n" + blob.strip())


def run_rotation(app: str, extra: list, keys: dict, key_out, dry_run: bool) -> int:
    cmd = [app] + extra + [
        "se", "rotate-scp03",
        "--enc", keys["ENC"].hex(),
        "--mac", keys["MAC"].hex(),
        "--dek", keys["DEK"].hex(),
    ]
    if key_out:
        cmd += ["--key-out", key_out]
    cmd += ["--dry-run"] if dry_run else ["--confirm"]
    print(f"+ {' '.join(cmd)}", file=sys.stderr)
    return subprocess.run(cmd).returncode


# ---------- main ----------

def main() -> int:
    p = argparse.ArgumentParser(
        description="Derive SE05x per-device SCP03 keys (and optionally rotate the device)")
    p.add_argument("--master-key", required=True, metavar="HEX32",
                   help="16-byte AES master key as 32 hex chars")
    p.add_argument("--uid", metavar="HEX36",
                   help="18-byte SE UID as 36 hex chars; omit to read it from the device via --app")
    p.add_argument("--app", metavar="PATH",
                   help="path to se05x_crypto_app (enables UID auto-read and --rotate)")
    p.add_argument("--app-arg", action="append", default=[], metavar="ARG",
                   help="extra arg passed through to the CLI (e.g. --app-arg --port --app-arg "
                        "t1oi2c:/dev/i2c-3); repeatable")
    p.add_argument("--rotate", action="store_true",
                   help="after deriving, run `se rotate-scp03 --confirm` on the device")
    p.add_argument("--dry-run", action="store_true",
                   help="with --rotate: build the APDU but do not send / do not change keys")
    p.add_argument("--out", metavar="FILE",
                   help="write the derived key file here (derive-only mode)")
    p.add_argument("--key-out", metavar="FILE",
                   help="with --rotate: where the CLI should persist the new keys "
                        "(default: $EX_SSS_BOOT_SCP03_PATH)")
    p.add_argument("--show-kcv", action="store_true",
                   help="also print each derived key's KCV (diagnostic)")
    args = p.parse_args()

    master_key = parse_hex(args.master_key, "--master-key")
    if len(master_key) != 16:
        p.error(f"--master-key must be 32 hex chars (16 bytes), got {len(master_key) * 2}")

    if not args.uid and not args.app:
        p.error("provide --uid, or --app to read the UID from the device")
    if args.rotate and not args.app:
        p.error("--rotate requires --app")

    # Resolve UID (explicit or from device).
    if args.uid:
        uid = parse_hex(args.uid, "--uid")
        if len(uid) != 18:
            p.error(f"--uid must be 36 hex chars (18 bytes), got {len(uid) * 2}")
    else:
        uid = read_uid_from_device(args.app, args.app_arg)
    print(f"UID: {uid.hex()}", file=sys.stderr)

    keys = derive_scp03_keys(master_key, uid)

    if args.show_kcv:
        print("--- derived keys (KCV = what the SE will echo) ---", file=sys.stderr)
        for name, k in keys.items():
            print(f"  {name} {k.hex()}  KCV={kcv(k).hex()}", file=sys.stderr)
        print(file=sys.stderr)

    if args.rotate:
        rc = run_rotation(args.app, args.app_arg, keys, args.key_out, args.dry_run)
        if rc == 0:
            where = args.key_out or os.environ.get("EX_SSS_BOOT_SCP03_PATH",
                                                   "$EX_SSS_BOOT_SCP03_PATH")
            action = "would update" if args.dry_run else "updated"
            print(f"rotation {'previewed' if args.dry_run else 'OK'}; CLI {action} {where}",
                  file=sys.stderr)
        else:
            print(f"rotation failed (CLI exit {rc}); keys NOT changed", file=sys.stderr)
        return rc

    # Derive-only: emit the key file.
    text = key_file_text(keys)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text)
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
