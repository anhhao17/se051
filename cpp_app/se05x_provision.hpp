/**
 * @file se05x_provision.hpp
 * @brief SE05x provisioning operations built on top of the SSS API.
 *
 * This module provides the higher-level SE-specific provisioning flows that
 * sit on top of the cryptographic primitives in se05x_crypto.hpp and the
 * object-store CRUD in se05x_object_store.hpp, and cannot be done through the
 * standard PKCS#11 interface:
 *
 *   - Chip UID retrieval (device identity anchor)
 *   - Binding verification (prove the SE key matches a certificate)
 *   - Key generation with explicit object policy (immutable after creation)
 *
 * Single responsibility: SE-specific provisioning flows.  No TLS, no CA.
 * Cryptographic primitives (sign, verify, RNG) are in se05x_crypto.hpp;
 * persistent object CRUD is in se05x_object_store.hpp.
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
