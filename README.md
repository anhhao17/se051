# SE05x Crypto & Provisioning

CMake **superbuild** that cross-compiles an SE05x (SE051) secure-element RSA provisioning
CLI for Linux ARM targets (Raspberry Pi and similar, T=1 over I2C), using **NXP Plug & Trust**
(SSS API) with **mbedTLS 2.28 LTS** as the host crypto backend and the **NXP se05x-pkcs11**
module for a standard PKCS#11 interface.

## What the superbuild produces

The top-level `CMakeLists.txt` orchestrates three sub-builds in order:

| Target | Output | Description |
|---|---|---|
| `mbedtls`    | static `libmbedtls/x509/crypto.a` | Host crypto backend (v2.28 LTS) |
| `pkcs11_lib` | `libsss_pkcs11.so`               | NXP se05x-pkcs11 module, mbedTLS backend |
| `cpp_app`    | `se05x_crypto_app`               | C++ RSA provisioning CLI |

Fixed middleware options (match these to the hardware): `PTMW_Applet=SE05X_C`,
`PTMW_SE05X_Ver=07_02` (SE051/052), `PTMW_HostCrypto=MBEDTLS`, `PTMW_SE05X_Auth=PlatfSCP03`.

## `se05x_crypto_app` - the CLI

A single binary with two interchangeable crypto backends: the SSS API + mbedTLS directly,
or `libsss_pkcs11.so` via `--pkcs11`. Only one secure channel is opened per invocation
(SE05x allows only one Platform SCP03 channel at a time).

```
se05x_crypto_app [--pkcs11 <lib>] [--port <conn>] [--log <file>] <group> <command> [options]

  rng <nbytes>
  se  uid
  rsa genkey         [--id <hex>=0xFE000001] [--bits 2048|3072|4096] [--force] [--pem]
  rsa pub            [--id <hex>] [--out <file>] [--pem]
  rsa sign           [--id <hex>] --in <file>  [--out <file>]
  rsa verify         [--id <hex>] --in <file>  --sig <file>
  rsa encrypt        [--id <hex>] --in <file>  [--out <file>]
  rsa decrypt        [--id <hex>] --in <file>  [--out <file>]
  rsa csr            [--id <hex>] --subject "CN=...,O=..."
  rsa write-cert     [--id <hex>] --in <cert.der>     (SSS only)
  rsa verify-binding [--id <hex>] --cert <cert.der>   (SSS only)
```

- `--pkcs11 <lib>` routes standard crypto through `libsss_pkcs11.so`
  (`CKM_SHA256_RSA_PKCS`, `CKM_RSA_PKCS_OAEP`). Without it, SSS + mbedTLS are used directly.
- `se uid`, `rsa write-cert`, `rsa verify-binding` always use SSS and reject `--pkcs11`.
- `--log <file>` redirects result output (hex, PEM, `VERIFY OK`, UID) to a file;
  timestamped status lines (`[i]/[+]/[!]`) always go to stderr. Without `--log`, result
  output goes to stdout.
- Connect string via `--port` or `$EX_SSS_BOOT_SSS_PORT` (e.g. `/dev/i2c-1:0x48`).

Provisioning design and milestones live in [`docs/provisioning.md`](docs/provisioning.md) and
[`docs/provisioning_plan.md`](docs/provisioning_plan.md).

## Prerequisites

### Submodules

```bash
git submodule update --init --recursive
```

- `ext/mbedtls/` - mbedTLS v2.28 LTS (do not bump to 3.x; see `CLAUDE.md`).
- `ext/plug-and-trust/` - NXP Plug & Trust mini package.
- `ext/se05x-pkcs11/` - NXP se05x-pkcs11 (only its `pkcs11` headers sub-submodule is used).

### Cross-compiler toolchains

| Target | Toolchain file |
|---|---|
| armhf (32-bit ARM hard-float) | `armhf-toolchain.cmake` |
| aarch64 (64-bit ARM) | `aarch64-toolchain.cmake` |

The toolchain files point at the cross GCC and its sysroot; edit `TOOLCHAIN_ROOT` to match
your install.

## Build

```bash
# armhf (32-bit ARM hard-float)
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=armhf-toolchain.cmake
cmake --build build

# aarch64 (64-bit ARM)
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=aarch64-toolchain.cmake
cmake --build build

# Native host build (x86_64, for development)
cmake -S . -B build
cmake --build build
```

Installed artifacts stage under `build/stage/` (`bin/se05x_crypto_app`,
`lib/libsss_pkcs11.so`).

### Build options

| Option | Default | Effect |
|---|---|---|
| `-DBUILD_JOBS=N`     | 2   | Parallelism of ExternalProject build steps |
| `-DSE05X_STRIP=ON`   | ON  | Strip installed binaries |
| `-DSE05X_DEBUG_LOG=` | OFF | Enable Plug & Trust verbose flow logging |

The app sub-builds compile size-optimized (`-Os`, `-ffunction-sections -fdata-sections`
with `-Wl,--gc-sections`, stripped) - important on memory-constrained ARM32 targets.
Without an explicit build type CMake emits **no** `-O` flag (i.e. `-O0`), which on this
target roughly doubled the binary and slowed the host-side SCP03 AES-CMAC; the superbuild
sets `CMAKE_BUILD_TYPE=Release` for both app sub-builds to avoid that.

**Clean rebuild** after a submodule version change: `rm -rf build` - ExternalProject stamp
caching will not otherwise detect the source change.

## Running

Copy the binary (and the PKCS#11 module, if used) to the target:

```bash
scp build/stage/bin/se05x_crypto_app pi@<host>:/home/pi/
scp build/stage/lib/libsss_pkcs11.so  pi@<host>:/home/pi/

# 32 random bytes from the SE TRNG
ssh pi@<host> './se05x_crypto_app --port /dev/i2c-1:0x48 rng 32'

# Provision an RSA-2048 identity key (idempotent) and emit a CSR
./se05x_crypto_app --port /dev/i2c-1:0x48 rsa genkey --id 0xFE000001 --bits 2048
./se05x_crypto_app --port /dev/i2c-1:0x48 rsa csr --id 0xFE000001 \
    --subject "CN=device-001,O=Acme" --out /home/pi/dev.csr

# Same crypto via the PKCS#11 module
./se05x_crypto_app --pkcs11 ./libsss_pkcs11.so --port /dev/i2c-1:0x48 rsa sign \
    --id 0xFE000001 --in payload.bin --out payload.sig
```

## Project structure

```
.
├── CMakeLists.txt           # Superbuild - mbedTLS → pkcs11_lib → cpp_app
├── armhf-toolchain.cmake    # Cross-toolchain for 32-bit ARM hard-float
├── aarch64-toolchain.cmake  # Cross-toolchain for 64-bit ARM
├── cpp_app/                 # se05x_crypto_app - RSA provisioning CLI
│   ├── main.cpp             # Backend selection + session lifecycle
│   ├── cli.cpp/.hpp         # Arg parsing and command dispatch
│   ├── crypto_backend.*     # ICryptoBackend: Pkcs11Backend / SssBackend
│   ├── se05x_crypto.*       # RsaKey + Session SSS RAII wrappers
│   ├── se05x_provision.*    # UID, cert storage, key↔cert binding check
│   ├── pkcs11_ctx.*         # RAII PKCS#11 session (dlopen)
│   ├── csr.cpp              # PKCS#10 CSR builder (mbedTLS ASN.1)
│   └── log.hpp              # Global timestamped logger (LOG_* macros)
├── pkcs11_lib/              # Builds libsss_pkcs11.so (OpenSSL → mbedTLS swap)
├── docs/                    # Provisioning design + implementation plan
├── examples/                # Standalone reference demos (not built by the superbuild)
│   ├── c_demo/              # C demo: EC + RSA + RNG via SSS (ex_sss_entry)
│   └── pkcs11_demo/         # C PKCS#11 demo suite (dlopen, 10 categories)
└── ext/
    ├── mbedtls/             # mbedTLS v2.28 LTS (submodule)
    ├── plug-and-trust/      # NXP Plug & Trust mini package (submodule)
    └── se05x-pkcs11/        # NXP se05x-pkcs11 (submodule)
```

## Key IDs (SE object store)

| ID | Purpose |
|---|---|
| `0xFE000001` | CLI default RSA key |
| `0xFE000001` | Production device identity RSA key |
| `0xFE000002` | Production device leaf certificate (DER) |

Demo/reference keys in `examples/` use the `0xEF000000-0xEFFFFFFF` test range and are erased
before each run. `rsa genkey` is idempotent: an existing key is reused unless `--force` is given.

See `CLAUDE.md` for the non-obvious build details (mbedTLS 2.x backend swap, SCP03/CMAC
requirement, SPKI format, CSR assembly).
