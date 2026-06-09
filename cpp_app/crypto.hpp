/**
 * @file crypto.hpp
 * @brief Crypto layer: the backend-agnostic RSA interface over the SE05x.
 *
 * ICryptoBackend is the single abstraction the API layer (se05x::Se05x) talks
 * to.  It is implemented by the two concrete backends in the layer below:
 *
 *   - SssBackend     (sss.hpp)         NXP SSS API + mbedTLS directly.
 *   - Pkcs11Backend  (pkcs11_ctx.hpp)  libsss_pkcs11.so via dlopen.
 *
 * All message-level methods accept the full plaintext/message; backends hash
 * internally so callers never pre-hash.  Both backends produce and consume
 * identical on-wire formats - a signature from one verifies under the other.
 */

#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace se05x {

/** @brief RSA key size in bits. */
enum class RsaBits { Rsa2048 = 2048, Rsa3072 = 3072, Rsa4096 = 4096 };

/**
 * @brief SE05x object policy for RSA keys (applied at creation, immutable after).
 *
 * @c Full for development/test keys; @c SignOnly / @c SignDecrypt for production
 * (SCP03-required, non-exportable, non-deletable).  Honoured only by the SSS
 * backend - the PKCS#11 backend ignores it.
 */
enum class KeyPolicy { Full, SignOnly, SignDecrypt };

} // namespace se05x

/**
 * @brief Abstract RSA crypto interface over the NXP SE05x.
 */
class ICryptoBackend {
public:
    virtual ~ICryptoBackend() = default;

    /** @brief Generate @p n random bytes from the SE hardware TRNG. */
    virtual std::vector<uint8_t> getRandom(size_t n) = 0;

    /** @brief Return true if an RSA key pair exists at @p id. */
    virtual bool keyExists(uint32_t id) = 0;

    /** @brief Erase the key pair at @p id.  No-op if the key does not exist. */
    virtual void deleteKey(uint32_t id) = 0;

    /**
     * @brief Generate and persist an RSA key pair on the SE.
     * @param policy  Applied at creation (SSS path only; ignored by PKCS#11).
     */
    virtual void generateKey(uint32_t id, se05x::RsaBits bits,
                             se05x::KeyPolicy policy = se05x::KeyPolicy::Full) = 0;

    /** @brief Return the public key at @p id as SubjectPublicKeyInfo DER. */
    virtual std::vector<uint8_t> getSpki(uint32_t id) = 0;

    /**
     * @brief Sign @p msg with RSASSA-PKCS1-v1_5 / SHA-256 (hashes internally).
     * @return Raw PKCS#1 v1.5 signature bytes.
     */
    virtual std::vector<uint8_t> sign(uint32_t id, const std::vector<uint8_t> &msg) = 0;

    /** @brief Verify a RSASSA-PKCS1-v1_5 / SHA-256 @p sig over @p msg. */
    virtual bool verify(uint32_t id, const std::vector<uint8_t> &msg,
                        const std::vector<uint8_t> &sig) = 0;

    /** @brief Build a PEM PKCS#10 CSR for the key at @p id. */
    virtual std::string makeCsr(uint32_t id, const std::string &subjectDn) = 0;
};

#endif // CRYPTO_HPP
