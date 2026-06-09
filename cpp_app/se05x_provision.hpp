/**
 * @file se05x_provision.hpp
 * @brief SE05x provisioning operations built on top of the SSS API.
 *
 * This module provides the SE-specific operations that sit on top of the
 * cryptographic primitives in se05x_crypto.hpp and cannot be done through
 * the standard PKCS#11 interface:
 *
 *   - Chip UID retrieval
 *   - Idempotent object existence check (for safe re-provisioning)
 *   - Persistent binary storage for DER certificates
 *   - Binding verification (prove the SE key matches a certificate)
 *   - Key generation with explicit object policy (immutable after creation)
 *
 * Single responsibility: SE-specific management.  No TLS, no CA, no logging.
 * Cryptographic primitives (sign, verify, RNG) are in se05x_crypto.hpp.
 */

#pragma once
#include "se05x_crypto.hpp"
#include <cstdint>
#include <vector>

namespace se05x {

/**
 * @brief SE05x object policy for RSA keys.
 *
 * Policies are applied at key-creation time and are immutable after the fact.
 * Use @c Full for development/testing; use @c SignDecrypt or @c SignOnly for
 * production keys (enforces SCP03-required, non-exportable, non-deletable).
 */
enum class KeyPolicy {
    Full,        ///< No restrictions. Suitable for test keys.
    SignOnly,    ///< Sign only; SCP03 required; non-exportable; non-deletable.
    SignDecrypt, ///< Sign + decrypt; SCP03 required; non-exportable; non-deletable.
};

/**
 * @brief Read the SE05x 18-byte chip unique identifier.
 *
 * The UID is permanently set in the SE at manufacture and cannot be
 * changed.  It is used as a device identity anchor.
 *
 * @param s  Active session.
 * @return   18-byte UID vector.
 * @throws CryptoError on SE failure.
 */
std::vector<uint8_t> readUid(Session &s);

/**
 * @brief Non-destructively check whether a SE object exists.
 *
 * Use this before genkey to implement idempotency: if the key already exists
 * and @c --force is not given, skip generation and return the existing key.
 *
 * @param s   Active session.
 * @param id  SE05x object ID to query.
 * @return    true if an object with @p id exists on the SE.
 */
bool objectExists(Session &s, uint32_t id);

/**
 * @brief Write a DER certificate (or arbitrary blob) as a binary SE object.
 *
 * If an object already exists at @p id it is erased first so the write is
 * idempotent.  The object is stored as @c kSSS_CipherType_Binary /
 * @c kKeyObject_Mode_Persistent.
 *
 * @param s    Active session.
 * @param id   SE05x object ID.
 * @param der  DER-encoded certificate bytes.
 * @throws CryptoError on SE failure.
 */
void writeCert(Session &s, uint32_t id, const std::vector<uint8_t> &der);

/**
 * @brief Write a plain binary blob to a persistent, rewritable SE object.
 * @param s      Active session.
 * @param id     SE05x object ID.
 * @param data   Bytes to store.
 * @param force  If the object already exists: erase+replace when true; otherwise
 *               leave it untouched.
 * @return       true if written, false if it already existed and @p force was false.
 * @throws CryptoError on SE failure.
 */
bool writeBinary(Session &s, uint32_t id, const std::vector<uint8_t> &data, bool force);

/**
 * @brief Read a binary SE object back.
 * @throws CryptoError if the object does not exist or cannot be read.
 */
std::vector<uint8_t> readBinary(Session &s, uint32_t id);


/**
 * @brief Verify that the RSA private key at @p keyId corresponds to the
 *        public key embedded in @p certDer.
 *
 * Algorithm:
 *   1. Generate 32 random bytes (hardware TRNG).
 *   2. Sign the SHA-256 hash of those bytes with the SE private key.
 *   3. Parse @p certDer with mbedTLS and extract the public key.
 *   4. Verify the signature against that public key.
 *
 * A true result proves the SE holds the private key matching the certificate.
 *
 * @param s        Active session.
 * @param keyId    SE05x object ID of an RSA key pair.
 * @param certDer  DER-encoded X.509 certificate containing the expected public key.
 * @return         true if the SE key and certificate public key match.
 * @throws std::runtime_error if @p certDer cannot be parsed.
 */
bool verifyBindingRsa(Session &s, uint32_t keyId, const std::vector<uint8_t> &certDer);

/**
 * @brief Generate an RSA key pair with a specific SE05x object policy.
 *
 * If @p policy is @c KeyPolicy::Full the key is generated with no
 * restrictions (equivalent to RsaKey::generate with nullptr policy).
 * Otherwise the serialized policy is passed to the SE at key-creation
 * time (immutable afterwards):
 *
 *  - @c SignOnly    : sign + SCP03-required; no decrypt, no export, no delete
 *  - @c SignDecrypt : sign + decrypt + SCP03-required; no export, no delete
 *
 * @param s       Active session.
 * @param keyId   SE object ID.
 * @param bits    RSA key size.
 * @param policy  Policy to enforce.
 * @return        Opened RsaKey handle (owns_ = true).
 * @throws CryptoError on SE failure.
 */
RsaKey generateKeyWithPolicy(Session &s, uint32_t keyId, RsaBits bits, KeyPolicy policy);

} // namespace se05x
