# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A CMake **superbuild** that cross-compiles a comprehensive SE051 crypto demo for ARM Linux targets
(Raspberry Pi over T=1 I2C). It orchestrates three things:

1. **mbedTLS** (`ext/mbedtls` submodule, **v2.28 LTS**) — cross-compiled static, installed into
   `${CMAKE_BINARY_DIR}/mbedtls`. The host crypto backend.
2. **`app/`** — C demo (`demo_se051`): EC keygen/sign/verify/ECDH/CSR, RSA keygen/sign/verify/
   enc-dec/CSR, hardware RNG. Entry point `ex_sss_entry()`.
3. **`cpp_app/`** — C++ demo (`se05x_crypto_app`): same operations via RAII wrappers (`EcKey`,
   `RsaKey`, `Session`).

## Submodules

```bash
git submodule update --init --recursive   # after a fresh clone
```

- `ext/plug-and-trust/` — NXP/plug-and-trust ("mini" Plug & Trust package; `sss/`, `hostlib/`).
  Currently at v04.07.01.
- `ext/mbedtls/` — Mbed-TLS, pinned to the **v2.28 LTS** line. **Do not bump to 3.x** without
  also flipping `SSS_HAVE_MBEDTLS_2_X` (see "mbedTLS backend" below).

## Build

The superbuild forwards `CMAKE_TOOLCHAIN_FILE` to every sub-build automatically. Pass it at the
top level to cross-compile; omit for a native host build.

```bash
# aarch64 cross-compile
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=aarch64-toolchain.cmake
cmake --build build              # builds mbedTLS, then demo_se051 + se05x_crypto_app

# armhf cross-compile
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=armhf-toolchain.cmake
cmake --build build

# native host
cmake -S . -B build
cmake --build build
```

- `-DBUILD_JOBS=N` controls parallelism of ExternalProject build steps (default 2).
- Clean rebuild after changing a submodule version: `rm -rf build` (ExternalProject caches
  stamps and will not otherwise notice the source change).
- Toolchain files live at `aarch64-toolchain.cmake` and `armhf-toolchain.cmake`.
  The superbuild resolves relative paths to absolute before forwarding, so short names work.

## mbedTLS backend (the non-obvious part)

The NXP mini package is **OpenSSL-first**: its README says "only OpenSSL is supported", and its
build glue (`ext/plug-and-trust/simw_lib.cmake`) hardcodes the OpenSSL SSS sources while
`ext/plug-and-trust/ecc_example/CMakeLists.txt` links `ssl crypto`. **But the mbedTLS path is fully
implemented in source** (`sss/src/mbedtls/fsl_sss_mbedtls_apis.c`, ~132 KB incl. its own keystore)
and the `MBEDTLS` option + feature flags exist — only the example's CMake wiring is missing.

Rather than patch the submodule, `app/CMakeLists.txt` and `cpp_app/CMakeLists.txt` are thin
wrappers that each:

1. Set `SSS_HAVE_MBEDTLS_2_X ON` **before** including `simw_lib.cmake`. The SSS code selects
   the 2.x vs 3.x mbedTLS API surface (`config.h` vs `mbedtls_config.h`, public vs
   `MBEDTLS_PRIVATE` struct fields, `pk_parse_key` arity) via this flag, which
   `simwlib_cmake_options.cmake` leaves unset (→ 0 = 3.x). Our submodule is 2.28, so it must be 1.
2. `include()` `simw_lib.cmake` to reuse its source/include lists and `fsl_sss_ftr.h` generation.
3. Remove `fsl_sss_openssl_apis.c` + `keystore_openssl.c` from `SIMW_SE_SOURCES` and add
   `fsl_sss_mbedtls_apis.c` (the mbedTLS keystore lives inside that file).
4. Link the static `libmbedtls/libmbedx509/libmbedcrypto` from the superbuild's mbedTLS prefix.

So switching the crypto backend is **not** just `-DPTMW_HostCrypto=...`; it requires this wrapper.

## Fixed PTMW options

Passed to both sub-builds — match the hardware/middleware when changing:

- `PTMW_Applet=SE051_H`
- `PTMW_SE05X_Ver=07_02`  (07_xx = SE051/SE052; 03_XX = SE050)
- `PTMW_HostCrypto=MBEDTLS`
- `PTMW_SE05X_Auth=PlatfSCP03`  (Platform SCP03 secure channel)

## SSS public key format

`sss_key_store_get_key()` returns **SubjectPublicKeyInfo (SPKI) DER** for **both EC and RSA**
(confirmed from `grsa2kPubHeader[]` in `fsl_sss_util_asn1_der.c`). The CSR code in `demo_ec.c`,
`demo_rsa.c`, and `cpp_app/csr.cpp` all use the SE output directly as the SubjectPublicKeyInfo
field — no wrapping needed.

## CSR implementation

Both the C and C++ CSR builders use `mbedtls/asn1write.h` to write DER backwards into a buffer.
They use mbedTLS APIs for the non-trivial parts:

- `mbedtls_x509_string_to_names()` / `mbedtls_x509_write_names()` — subject DN encoding
- `mbedtls_asn1_write_algorithm_identifier_ext(..., 0, 0)` — ECDSA AlgId (no parameters)
- `mbedtls_asn1_write_algorithm_identifier(..., 0)` — RSA AlgId (explicit NULL parameters)
- `mbedtls_asn1_write_bitstring()` — signature BIT STRING
- `mbedtls_pem_write_buffer()` — DER → PEM encoding

CSRs are written to `/tmp/ec_csr.der`, `/tmp/ec_csr.pem`, `/tmp/rsa_csr.der`, `/tmp/rsa_csr.pem`.
Verify on target: `openssl req -in /tmp/ec_csr.pem -noout -text`

## PKCS#11 branch (`feat/pkcs11`)

Adds the NXP se05x-pkcs11 PKCS#11 module on top of the existing superbuild.

**New submodule**: `ext/se05x-pkcs11` — NXP se05x-pkcs11 repo (shallow).
Only its `pkcs11` sub-submodule is initialized (OASIS PKCS#11 2.40 headers);
`simw_lib` inside it is NOT initialized — we use `ext/plug-and-trust` instead.

**`pkcs11_lib/CMakeLists.txt`**: Mirrors `app/CMakeLists.txt` pattern — sets
`SIMW_LIB_DIR` to `ext/plug-and-trust`, sets `SSS_HAVE_MBEDTLS_2_X ON`,
includes `simw_lib.cmake`, swaps OpenSSL→mbedTLS, globs `ext/se05x-pkcs11/se_pkcs11/*.c`,
builds `libsss_pkcs11.so`, links mbedTLS. Defines `PKCS11_LIBRARY` and `PKCS11_SESSION_OPEN`.

**`pkcs11_example/pkcs11_demo.c`**: Pure C, uses `dlopen` to load the library at runtime.
Include entry point is `cryptoki.h` (from `se_pkcs11/`), which sets required platform macros
then includes `pkcs11.h` from `pkcs11/published/2-40-errata-1/`.

Key PKCS#11 notes:
- `CKM_ECDSA_SHA256` returns raw r||s (64 B for P-256), not DER
- Key label format for NXP: `"sss:0xEF000020"` maps to SE object ID `0xEF000020`
- `CKA_EC_PARAMS` = DER OID of the named curve: `{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07}` for P-256
- Demo key uses ID `0xEF000020` (outside the range used by `app/` demo keys)

## Provisioning branch (`feat/privisioning`)

Builds on `feat/pkcs11`. Adds SE-specific provisioning subcommands and structured output logging.

**Current command set** (`cpp_app/`):

```
se05x_crypto_app [--pkcs11 <lib>] [--port <conn>] [--log <file>] <group> <command> [options]

  rng <nbytes>
  se  uid
  rsa genkey [--id <hex>=0xFE000001] [--bits 2048|3072|4096] [--force] [--pem]
  rsa pub / sign / verify / encrypt / decrypt / csr
  rsa write-cert     --id <id> --in <cert.der>       # SSS-only
  rsa verify-binding --id <id> --cert <cert.der>      # SSS-only
```

**Provisioning subcommands** — all SSS-only; do not accept `--pkcs11`:
- `se uid` — reads 18-byte chip UID (`se05x::readUid()`)
- `rsa write-cert` — writes DER cert as binary SE object; idempotent (erase-then-write)
- `rsa verify-binding` — TRNG nonce → SE sign → mbedTLS verify against cert pubkey

**Idempotent genkey**: checks `se05x::objectExists()` before generating; with an existing key
and no `--force`, returns existing SPKI and exits 0 cleanly.

**Production key IDs**: default CLI ID is `0xFE000001` (test range).
Pass `--id 0xF0000001` (key) / `--id 0xF0000002` (cert) for production provisioning objects.

**`--log <file>` logging** (`cpp_app/log.hpp`, `Log` class):
- Without `--log`: result output (hex, VERIFY OK, PEM, UID) → stdout; status `[i]/[+]/[!]` → stderr.
- With `--log <file>`: result output → file; status → both stderr and file.
- `Log(nullptr)` = stdout mode; `Log("path")` = file mode. Non-copyable RAII.

**SCP03 channel conflict prevention**: `preParse()` + `isPkcs11Command()` in `main.cpp`
determine the backend before any session opens. Only one of SSS or PKCS#11 is ever opened.

**Not yet implemented**: `set-policy` (lock key to sign-only), `rotate-scp03` (per-device
SCP03 key KDF from UID — irreversible; treat carefully).

**Plan/status**: see `docs/provisioning_plan.md` and `docs/provisioning.md`.
M1 (build), M2 (PKCS#11), M4 (provisioning cmds) done. M3 (SE mgmt), M5-M6 not yet started.

## Key ID safe range

Demo keys use IDs in `0xEF000000–0xEFFFFFFF` (the `MAKE_TEST_ID` range per `ex_sss_objid.h`).
Each demo function erases the key ID before allocating so re-runs are clean.

## Notes

- Out-of-source: all artifacts live under `build/`.
- The toolchain file restricts find modes to the sysroot (`CMAKE_FIND_ROOT_PATH_MODE_*`),
  so libraries/headers/packages resolve against the ARM target, not the host.
- `simw_lib.cmake` regenerates `ext/plug-and-trust/fsl_sss_ftr.h` on configure (writes into the
  submodule). That's expected — it's a generated file, mirroring upstream's own build.
- mbedTLS 2.28: use `mbedtls_sha256_ret()` (returns int), not `mbedtls_sha256()` (void/deprecated).
