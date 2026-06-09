/**
 * @file crypto_backend.hpp
 * @brief Abstract crypto backend and its two concrete implementations.
 *
 * ICryptoBackend decouples Cli from the underlying crypto path.
 *
 * Pkcs11Backend - libsss_pkcs11.so via dlopen.
 *   Sign/verify : CKM_SHA256_RSA_PKCS  (SE hashes internally; pass full message)
 *   Enc/dec     : CKM_RSA_PKCS_OAEP / SHA-256 / MGF1-SHA256
 *
 * SssBackend    - NXP SSS API + mbedTLS directly (no PKCS#11 library needed).
 *   Sign/verify : SHA-256 computed by mbedTLS, digest signed by SE
 *   Enc/dec     : RSA-OAEP-SHA256 via sss_asymmetric
 *
 * Both backends produce and consume identical on-wire formats.  Signatures
 * created by one backend can be verified by the other.
 */

#pragma once

#include "pkcs11_ctx.hpp"
#include "se05x_crypto.hpp"
#include "se05x_provision.hpp"

#include <cstdint>
#include <string>
#include <vector>

/**
 * @brief Abstract RSA crypto interface over the NXP SE05x.
 *
 * All message-level methods accept the full plaintext/message; backends
 * handle hashing internally so callers never pre-hash.
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
     *
     * @param id      SE object ID.
     * @param bits    Key size (2048 / 3072 / 4096).
     * @param policy  Object policy applied at creation time (SSS path only;
     *                ignored by the PKCS#11 backend).
     */
    virtual void generateKey(uint32_t id, se05x::RsaBits bits,
                             se05x::KeyPolicy policy = se05x::KeyPolicy::Full) = 0;

    /** @brief Return the public key at @p id as SubjectPublicKeyInfo DER. */
    virtual std::vector<uint8_t> getSpki(uint32_t id) = 0;

    /**
     * @brief Sign @p msg with RSASSA-PKCS1-v1_5 / SHA-256.
     *
     * Pass the full message; the backend hashes internally.
     * Returns raw PKCS#1 v1.5 signature bytes.
     */
    virtual std::vector<uint8_t> sign(uint32_t id, const std::vector<uint8_t> &msg) = 0;

    /**
     * @brief Verify a RSASSA-PKCS1-v1_5 / SHA-256 @p sig over @p msg.
     * @return true if the signature is valid.
     */
    virtual bool verify(uint32_t id, const std::vector<uint8_t> &msg,
                        const std::vector<uint8_t> &sig) = 0;

    /** @brief Encrypt @p plain with RSA-OAEP-SHA256. */
    virtual std::vector<uint8_t> encrypt(uint32_t                    id,
                                         const std::vector<uint8_t> &plain) = 0;

    /** @brief Decrypt @p cipher with RSA-OAEP-SHA256. */
    virtual std::vector<uint8_t> decrypt(uint32_t                    id,
                                         const std::vector<uint8_t> &cipher) = 0;

    /**
     * @brief Build a PEM PKCS#10 CSR for the key at @p id.
     * @param subjectDn  Subject DN in OpenSSL format, e.g. "CN=foo,O=bar".
     */
    virtual std::string makeCsr(uint32_t id, const std::string &subjectDn) = 0;
};

/**
 * @brief PKCS#11 backend - all operations through @c libsss_pkcs11.so.
 */
class Pkcs11Backend final : public ICryptoBackend {
public:
    /**
     * @param libPath  Full path to @c libsss_pkcs11.so.
     * @throws Pkcs11Error if the library cannot be loaded or initialized.
     */
    explicit Pkcs11Backend(const std::string &libPath);

    std::vector<uint8_t> getRandom(size_t n) override;
    bool                 keyExists(uint32_t id) override;
    void                 deleteKey(uint32_t id) override;
    void generateKey(uint32_t id, se05x::RsaBits bits,
                     se05x::KeyPolicy policy = se05x::KeyPolicy::Full) override;
    std::vector<uint8_t> getSpki(uint32_t id) override;
    std::vector<uint8_t> sign(uint32_t id, const std::vector<uint8_t> &msg) override;
    bool                 verify(uint32_t id, const std::vector<uint8_t> &msg,
                                const std::vector<uint8_t> &sig) override;
    std::vector<uint8_t> encrypt(uint32_t id, const std::vector<uint8_t> &plain) override;
    std::vector<uint8_t> decrypt(uint32_t                    id,
                                 const std::vector<uint8_t> &cipher) override;
    std::string          makeCsr(uint32_t id, const std::string &subjectDn) override;

private:
    Pkcs11Ctx ctx_;
};

/**
 * @brief SSS + mbedTLS backend - no PKCS#11 library required.
 *
 * @note The Session must outlive this object.
 */
class SssBackend final : public ICryptoBackend {
public:
    explicit SssBackend(se05x::Session &session);

    std::vector<uint8_t> getRandom(size_t n) override;
    bool                 keyExists(uint32_t id) override;
    void                 deleteKey(uint32_t id) override;
    void generateKey(uint32_t id, se05x::RsaBits bits,
                     se05x::KeyPolicy policy = se05x::KeyPolicy::Full) override;
    std::vector<uint8_t> getSpki(uint32_t id) override;
    std::vector<uint8_t> sign(uint32_t id, const std::vector<uint8_t> &msg) override;
    bool                 verify(uint32_t id, const std::vector<uint8_t> &msg,
                                const std::vector<uint8_t> &sig) override;
    std::vector<uint8_t> encrypt(uint32_t id, const std::vector<uint8_t> &plain) override;
    std::vector<uint8_t> decrypt(uint32_t                    id,
                                 const std::vector<uint8_t> &cipher) override;
    std::string          makeCsr(uint32_t id, const std::string &subjectDn) override;

private:
    se05x::Session &session_;
};
