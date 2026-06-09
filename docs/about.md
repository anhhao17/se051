# What this is: the SE05x device-identity tool

*A plain-language guide to the secure-element chip and the tool that manages it. Written for product,
program, and non-engineering readers.*

---

## The short version

Our product contains a tiny dedicated **security chip** (an NXP **SE05x**). It acts like a built-in,
tamper-resistant safe for the device's most important secret: its private cryptographic identity.

We built a small command-line **tool** (`se05x_crypto_app`) that runs on the device's main processor
and "talks to" that chip - to set up the device's identity during manufacturing, to prove that
identity later, and to perform everyday cryptographic tasks. This document explains both: what the
chip is, and what the tool does with it.

---

## Part 1 - What is the SE05x?

The SE05x is a **secure element**: a small, separate chip whose only job is to store secrets and do
cryptography in a way that's extremely hard to break into, even if someone physically has the device
in their hands.

The key ideas:

- **It holds a private key that never comes out.** The device's private key is generated *inside*
  the chip and physically cannot be exported. The tool can ask the chip to *use* the key (for
  example, to sign something), but it can never read the key itself. So even if the main device
  software is fully compromised, the private key stays protected.
- **It has a permanent, unique serial number.** Every chip has an 18-byte **UID** burned in at the
  factory that can't be changed. This gives each device a hardware-anchored identity.
- **It has a hardware random-number generator.** True randomness from dedicated hardware, which is
  the foundation of good cryptography (predictable "random" numbers are a classic way security
  fails).
- **It connects to the main processor over a simple internal wire** (a bus called I²C). The chip and
  the software talk over a **protected channel** so that the conversation between them can't be
  spied on or tampered with by other software on the device.
- **It does the heavy cryptographic math itself** - generating RSA key pairs, signing, verifying -
  so the main processor doesn't have to, and the secrets never leave the safe to do it.

Analogy: think of the SE05x as a **notary's stamp locked inside a safe that's bolted into the
product**. You can hand documents through a slot and get them stamped, and you can verify a stamp is
genuine - but you can never take the stamp out, copy it, or see how it's made.

---

## Part 2 - What our application does

`se05x_crypto_app` is the tool that uses the chip. It's a command-line program: you run it with a
command and it performs one operation against the chip, then exits. It's used in two main moments:

1. **During provisioning** (in manufacturing, or first-time setup) - to give the device its identity.
2. **In normal operation or servicing** - to use that identity and manage stored data.

Its capabilities fall into a few groups.

### Giving the device its identity

- **Generate the device's private key** inside the chip (`rsa genkey`). This creates the RSA key
  pair that *is* the device's identity. It's done once per device. The tool is careful here: if a key
  already exists it won't silently overwrite it (you have to explicitly force that), so you can't
  accidentally destroy a device's identity by re-running setup.
- **Export the public key** (`rsa pub`). The public half is meant to be shared - this hands it out in
  standard formats other systems expect.
- **Produce a certificate request** (`rsa csr`). This creates the standard paperwork (a "CSR") that
  you send to a Certificate Authority so it can issue the device an official certificate - the
  digital equivalent of a passport. The chip signs the request to prove it controls the key, without
  ever revealing the key.

### Proving and storing identity

- **Store the device's certificate on the chip** (`rsa write-cert`) so the device's passport lives
  alongside its key.
- **Prove the key matches the certificate** (`rsa verify-binding`). This confirms that the private
  key locked inside *this specific chip* really is the one the certificate was issued for - i.e. the
  passport belongs to this device and isn't a copy. It does this by having the chip sign a fresh
  random challenge and checking the signature against the certificate.
- **Read the chip's permanent serial number** (`se uid`).

### Everyday cryptographic tasks

- **Sign data** (`rsa sign`) - produce a tamper-proof signature over a file, proving it came from
  this device and wasn't altered.
- **Verify a signature** (`rsa verify`) - check that a signature is genuine.
- **Generate true random numbers** (`rng`) - from the chip's hardware randomness source.

### Storing small bits of device data

- **Write / read / verify a small data record on the chip** (`se write-info`, `read-info`,
  `verify-info`) - for storing things like a device-info blob in the chip's protected storage and
  later confirming it's intact.

### Managing the protected channel

- **Rotate the chip's master channel keys** (`se rotate-scp03`). The channel between the software and
  the chip is itself protected by a set of master keys; this command replaces them with new ones
  (for example, moving a device off shared factory keys onto unique production keys). This is a
  deliberately guarded, one-way operation with a preview mode and automatic backup, because it can't
  be undone.

---

## Part 3 - Two ways to talk to the chip

The same tool can reach the chip through **two interchangeable pathways**, and you pick one when you
run a command:

- **The direct pathway (default)** - the tool talks to the chip using NXP's own software library.
- **The standards pathway (`--pkcs11`)** - the tool talks through **PKCS#11**, an industry-standard
  interface that lots of security software understands. This is useful when the device needs to fit
  into existing tools and ecosystems that already speak that standard.

Both produce identical results - a signature made one way verifies the other way - so the choice is
about how the device fits into a larger system, not about what it can do. (A couple of chip-management
tasks, like reading the serial number or rotating the channel keys, always use the direct pathway.)

> *Note: only one secure conversation with the chip is allowed at a time, so the tool deliberately
> opens just one pathway per run.*

---

## Part 4 - A typical device lifecycle

Putting the pieces together, here's how the tool is normally used over a device's life:

1. **Birth (manufacturing):** generate the private key inside the chip → export the public key →
   create a certificate request → send it to the Certificate Authority → store the returned
   certificate on the chip. The device now has a hardware-protected identity.
2. **Optional hardening:** rotate the chip's channel keys from shared factory keys to unique
   production keys.
3. **Quality check:** verify the key matches the certificate, and read the serial number, to confirm
   the device was provisioned correctly.
4. **In the field:** use the identity for its real purpose - signing data, proving the device is
   genuine, generating randomness, and reading/verifying stored device info.

---

## Quick command reference (plain language)

| Command | What it does |
|---|---|
| `rng <n>` | Get `n` truly-random bytes from the chip |
| `se uid` | Read the chip's permanent serial number |
| `rsa genkey` | Create the device's private identity key inside the chip (one-time setup) |
| `rsa pub` | Export the public key (safe to share) |
| `rsa csr` | Produce a certificate request to send to a Certificate Authority |
| `rsa sign` | Sign a file with the device's key |
| `rsa verify` | Check that a signature is genuine |
| `rsa write-cert` | Store the device's certificate on the chip |
| `rsa verify-binding` | Prove the chip's key matches its certificate (this is the right device) |
| `se write-info` / `read-info` / `verify-info` | Store / read / confirm a small data record on the chip |
| `se rotate-scp03` | Replace the chip's master channel keys (guarded, one-way) |

---

## Mini glossary

- **Secure element / SE05x** - the dedicated security chip; the built-in safe.
- **Private key** - the device's secret. Lives inside the chip and never comes out.
- **Public key** - the shareable counterpart to the private key; used by others to verify the device.
- **Certificate** - the device's digital passport, issued by a Certificate Authority, linking its
  public key to its identity.
- **CSR (certificate signing request)** - the application form the device sends to get a certificate.
- **UID** - the chip's permanent, unique serial number.
- **Signing / signature** - a tamper-proof seal proving data came from the device and wasn't changed.
- **PKCS#11** - an industry-standard interface for talking to security hardware.
- **Channel keys (SCP03)** - the master keys that protect the private conversation between the
  software and the chip.