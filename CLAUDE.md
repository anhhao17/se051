# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A CMake **superbuild** that cross-compiles an SE05x (SE051) RSA provisioning CLI for ARM Linux
targets (Raspberry Pi and similar, T=1 over I2C). The top-level `CMakeLists.txt` orchestrates
three ExternalProjects, built in order:

1. **mbedTLS** (`ext/mbedtls`, **v2.28 LTS**) - cross-compiled static, installed into
   `${CMAKE_BINARY_DIR}/mbedtls`. The host crypto backend.
2. **`pkcs11_lib/`** → `libsss_pkcs11.so` - the NXP se05x-pkcs11 module, mbedTLS-backed.
3. **`cpp_app/`** → `se05x_crypto_app` - the C++ RSA provisioning CLI (the primary deliverable).

Installed artifacts stage under `build/stage/` (`bin/se05x_crypto_app`, `lib/libsss_pkcs11.so`).

The C reference demos under `examples/` (`c_demo`, `pkcs11_demo`) are **not** built by the
superbuild - they are standalone reference code with their own `CMakeLists.txt`.

## Submodules

```bash
git submodule update --init --recursive   # after a fresh clone
```

- `ext/plug-and-trust/` - NXP Plug & Trust "mini" package (`sss/`, `hostlib/`).
- `ext/mbedtls/` - pinned to the **v2.28 LTS** line. **Do not bump to 3.x** without also flipping
  `SSS_HAVE_MBEDTLS_2_X` (see "mbedTLS backend swap" below).
- `ext/se05x-pkcs11/` - NXP se05x-pkcs11. Only its `pkcs11` headers sub-submodule (OASIS PKCS#11
  2.40) is needed; its bundled `simw_lib` is intentionally **not** initialized - we use
  `ext/plug-and-trust` instead.

## Build

The superbuild forwards `CMAKE_TOOLCHAIN_FILE` to every sub-build automatically (resolving relative
paths to absolute first, so short names work). Pass it at the top level to cross-compile; omit for
a native host build.

```bash
# armhf cross-compile (the actual target - 32-bit ARM hard-float)
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=armhf-toolchain.cmake
cmake --build build              # builds mbedTLS, then pkcs11_lib + cpp_app

# aarch64 cross-compile
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=aarch64-toolchain.cmake

# native host (development)
cmake -S . -B build
```

Toolchain files (`armhf-toolchain.cmake`, `aarch64-toolchain.cmake`) point `TOOLCHAIN_ROOT` at a
cross GCC + sysroot; edit that path to match your install.

**Build options:**

| Option | Default | Effect |
|---|---|---|
| `-DBUILD_JOBS=N`        | 2   | Parallelism of ExternalProject build steps |
| `-DSE05X_STRIP=ON`      | ON  | Strip installed binaries |
| `-DSE05X_DEBUG_LOG=ON`  | OFF | Plug & Trust verbose flow logging (`FLOW_VERBOSE`, `NX_LOG_ENABLE_DEFAULT_DEBUG=1`) |

**Gotchas:**
- **Clean rebuild after a submodule version change:** `rm -rf build`. ExternalProject caches stamps
  and will not otherwise notice the source change. (`cpp_app`/`pkcs11_lib` use `BUILD_ALWAYS ON`,
  so their *own* source edits are picked up without this.)
- **Optimization is set explicitly.** Without an explicit build type CMake emits no `-O` flag
  (i.e. `-O0`) - which roughly doubled the binary and slowed host-side SCP03 AES-CMAC on ARM32. The
  superbuild forces `CMAKE_BUILD_TYPE=Release` + `-Os -ffunction-sections -fdata-sections` +
  `-Wl,--gc-sections` for `cpp_app`/`pkcs11_lib` (and section flags for mbedTLS so GC can drop
  unused archive code).

**Tests:** there is no host-side automated test suite. Verification is manual on hardware (e.g.
`rng 32` returns bytes; `openssl req -in <csr> -noout -text` validates a CSR).

## cpp_app architecture (the big picture)

`se05x_crypto_app` is a single binary with **two interchangeable crypto backends** behind one
abstract interface. Reading these files together explains the whole app:

- `crypto_backend.hpp` - `ICryptoBackend`: the strategy interface (genkey, sign, verify, encrypt,
  decrypt, csr, rng, getSpki, keyExists, deleteKey). Two implementations:
  - `SssBackend` - NXP SSS API + mbedTLS directly (digest computed host-side, then SE signs).
  - `Pkcs11Backend` - `libsss_pkcs11.so` via `dlopen` (`CKM_SHA256_RSA_PKCS` hashes on the SE;
    `CKM_RSA_PKCS_OAEP`). Both backends produce/consume identical on-wire formats.
- `main.cpp` - selects the backend and owns session lifecycle. **Critical constraint:** the SE05x
  allows only **one Platform SCP03 channel at a time**. Opening both an SSS session and PKCS#11
  `C_Initialize` resets whichever opened first, causing `0x6982` APDU errors. `preParse()` +
  `isPkcs11Command()` decide the backend *before* any session opens, so only one is ever opened.
- `cli.cpp` - arg parsing + dispatch. Crypto commands delegate to `ICryptoBackend` with no
  backend-specific branching. **SE-management commands (`se uid`, `rsa write-cert`,
  `rsa verify-binding`) are SSS-only** - they use the direct `se05x::Session` (`mgmt_`) and throw if
  invoked under `--pkcs11`, because a PKCS#11-only invocation opens no SSS session.
- `se05x_crypto.{hpp,cpp}` - `RsaKey` + `Session` RAII wrappers over the SSS API (RSA only; no EC).
- `se05x_provision.{hpp,cpp}` - SE-specific ops with no PKCS#11 equivalent: UID read, binary cert
  storage, key↔cert binding check.
- `pkcs11_ctx.{hpp,cpp}` - RAII PKCS#11 session.
- `csr.cpp` - PKCS#10 CSR assembly (see below).
- `log.hpp` - global logger (see "Logging").

### Logging

`Log` is a **global singleton** initialized once in `main()` via `Log::init(logPath)`; every TU
reaches it through the `LOG_DEBUG/INFO/OK/ERROR` macros (which capture `__FILE__`/`__LINE__` and
prepend a timestamp). Do **not** thread a `Log&` through constructors.

- Status lines (`[i]/[+]/[!]`, timestamped, with source location) always go to **stderr**; also to
  the log file when `--log` is active.
- Result data - hex, PEM, `VERIFY OK`, UID - goes through `Log::get().print()` / `.hex()` with no
  prefix (machine-readable). Without `--log` it goes to **stdout**; with `--log` it goes to the file.
- `LOG_DEBUG` is filtered out below the default `INFO` level.
- **Key material never prints to the terminal**: `rsa pub`/`genkey` only emit SPKI when `--out` is
  given.

## mbedTLS backend swap (the non-obvious part)

The NXP mini package is **OpenSSL-first**: its README says "only OpenSSL is supported", and
`ext/plug-and-trust/simw_lib.cmake` hardcodes the OpenSSL SSS sources. **But the mbedTLS path is
fully implemented in source** (`sss/src/mbedtls/fsl_sss_mbedtls_apis.c`, ~132 KB incl. its own
keystore) and the `MBEDTLS` option + feature flags exist - only the example CMake wiring is missing.

Rather than patch the submodule, **`cpp_app/CMakeLists.txt` and `pkcs11_lib/CMakeLists.txt`** are
thin wrappers that each:

1. Set `SSS_HAVE_MBEDTLS_2_X ON` **before** including `simw_lib.cmake`. The SSS code selects the
   2.x vs 3.x mbedTLS API surface (`config.h` vs `mbedtls_config.h`, public vs `MBEDTLS_PRIVATE`
   struct fields, `pk_parse_key` arity) via this flag, which `simwlib_cmake_options.cmake` leaves
   unset (→ 0 = 3.x). Our submodule is 2.28, so it must be 1.
2. `include()` `simw_lib.cmake` to reuse its source/include lists and `fsl_sss_ftr.h` generation.
3. Remove `fsl_sss_openssl_apis.c` + `keystore_openssl.c` from `SIMW_SE_SOURCES`, add
   `fsl_sss_mbedtls_apis.c` (the mbedTLS keystore lives inside that file).
4. Link the static `libmbedtls/libmbedx509/libmbedcrypto` from the superbuild's mbedTLS prefix.

So switching the crypto backend is **not** just `-DPTMW_HostCrypto=...`; it requires this wrapper.

## Fixed PTMW options

Passed to both `cpp_app` and `pkcs11_lib` (`PTMW_COMMON_ARGS` in the top-level `CMakeLists.txt`) -
match the hardware/middleware when changing:

- `PTMW_Applet=SE05X_C`
- `PTMW_SE05X_Ver=07_02`  (07_xx = SE051/SE052; 03_XX = SE050)
- `PTMW_HostCrypto=MBEDTLS`
- `PTMW_SE05X_Auth=PlatfSCP03`  (Platform SCP03 secure channel)

SCP03 static keys are read from a file via `EX_SSS_BOOT_SCP03_PATH`; session-key derivation
(AES-CMAC) runs in mbedTLS on the host - which is why mbedTLS **must** be built with
`MBEDTLS_CMAC_C` (injected via the auto-generated `mbedtls_user_config.h` in the superbuild).
Without CMAC the channel never opens even though I2C/ATR/select succeed.

## SSS public key format

`sss_key_store_get_key()` returns **SubjectPublicKeyInfo (SPKI) DER** directly (confirmed from
`grsa2kPubHeader[]` in `fsl_sss_util_asn1_der.c`). `cpp_app/csr.cpp` uses the SE output directly as
the CSR's `subjectPublicKeyInfo` field - no wrapping needed. The PKCS#11 path instead reads
`CKA_MODULUS`/`CKA_PUBLIC_EXPONENT` and rebuilds SPKI with mbedTLS (`pkcs11_ctx.cpp::getSpki`),
to avoid opening a parallel SSS session.

## CSR assembly

`csr.cpp` writes DER **backwards** into a buffer with `mbedtls/asn1write.h`, using mbedTLS for the
non-trivial parts: `mbedtls_x509_string_to_names()` / `mbedtls_x509_write_names()` (subject DN),
`mbedtls_asn1_write_algorithm_identifier(...)` (RSA `sha256WithRSAEncryption`, explicit NULL
params), `mbedtls_asn1_write_bitstring()` (signature), `mbedtls_pem_write_buffer()` (PEM).

Two signing paths share `buildCri` / `assembleCsr`: `makeCsrImpl` (SSS - sign a precomputed
digest) and `makeCsrFullSign` (PKCS#11 - pass full CRI bytes so `CKM_SHA256_RSA_PKCS` hashes on the
SE). `cpp_app` writes the CSR to stdout or `--out`; verify with
`openssl req -in <csr.pem> -noout -text`.

## PKCS#11 specifics

- Key label convention: `"sss:0xEF000020"` maps to SE object ID `0xEF000020` (`Pkcs11Ctx::label`).
- `signRsa`/`verifyRsa` use `CKM_SHA256_RSA_PKCS` (SE hashes internally) → pass the **full message**,
  not a digest. Output is raw PKCS#1 v1.5.
- Crypto ops use the two-step PKCS#11 idiom: call once with `nullptr` to query output size, allocate,
  call again.
- `examples/pkcs11_demo` additionally exercises EC: `CKM_ECDSA_SHA256` returns raw r‖s (64 B for
  P-256), not DER; `CKA_EC_PARAMS` is the named-curve OID DER.

## Provisioning commands & status

```
se05x_crypto_app [--pkcs11 <lib>] [--port <conn>] [--log <file>] <group> <command> [options]

  rng <nbytes>
  se  uid                                                  # 18-byte chip UID (SSS only)
  rsa genkey [--id <hex>=0xFE000001] [--bits 2048|3072|4096] [--force] [--pem]
  rsa pub / sign / verify / encrypt / decrypt / csr
  rsa write-cert     --id <id> --in <cert.der>             # SSS only; idempotent erase-then-write
  rsa verify-binding --id <id> --cert <cert.der>           # SSS only; TRNG nonce→SE sign→mbedTLS verify
```

- **Idempotent genkey**: checks `se05x::objectExists()` first; with an existing key and no
  `--force`, exits 0 cleanly (re-emits SPKI only if `--out` is set).
- **Key IDs**: CLI default `0xFE000001` (test range). Production provisioning uses `0xF0000001`
  (key) / `0xF0000002` (cert).
- **Connect string** via `--port` or `$EX_SSS_BOOT_SSS_PORT` (e.g. `/dev/i2c-1:0x48`).
- **Not yet implemented**: `set-policy` (lock key to sign-only), `rotate-scp03` (per-device SCP03
  key KDF from UID - irreversible; treat carefully).
- **Plan/status**: `docs/provisioning.md`, `docs/provisioning_plan.md`. M1 (build), M2 (PKCS#11),
  M4 (provisioning cmds) done; M3 (SE mgmt), M5–M6 not started.

## Key ID safe range

Reference/demo keys in `examples/` use `0xEF000000–0xEFFFFFFF` (the `MAKE_TEST_ID` range per
`ex_sss_objid.h`) and erase before allocating so re-runs are clean.

## Notes

- Out-of-source: all artifacts live under `build/` (staged into `build/stage/`).
- The toolchain files restrict find modes to the sysroot (`CMAKE_FIND_ROOT_PATH_MODE_*`), so
  libraries/headers/packages resolve against the ARM target, not the host.
- `simw_lib.cmake` regenerates `ext/plug-and-trust/fsl_sss_ftr.h` on configure (writes into the
  submodule). That's expected - it's a generated file mirroring upstream's own build.
- mbedTLS 2.28: use `mbedtls_sha256_ret()` (returns int), not `mbedtls_sha256()` (void/deprecated).
