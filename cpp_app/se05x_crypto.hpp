/**
 * @file se05x_crypto.hpp
 * @brief C++ wrapper around the NXP SSS API for the SE05x secure element.
 *
 * Provides RSA-2048/3072/4096 operations, hardware RNG, and PKCS#10 CSR
 * generation.  The private key never leaves the secure element.
 *
 * Responsibilities by class:
 *   - Session  : owns (borrows) the SSS boot context; gateway to the SE.
 *   - RsaKey   : sign, verify, encrypt, decrypt, CSR for one RSA key object.
 *
 * All failures are reported by throwing CryptoError.
 */

#ifndef SE05X_CRYPTO_HPP
#define SE05X_CRYPTO_HPP

#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

extern "C" {
#include <ex_sss_boot.h>
#include <fsl_sss_api.h>
}

namespace se05x {

/**
 * @brief Exception thrown on any SSS or mbedTLS failure.
 *
 * Carries the raw @c sss_status_t for callers that want to inspect the error
 * code rather than just the message string.
 */
class CryptoError : public std::runtime_error {
public:
    /**
     * @param what  Human-readable description of the failure.
     * @param st    The SSS status code (default: generic failure).
     */
    explicit CryptoError(const std::string &what,
                         sss_status_t st = kStatus_SSS_Fail)
        : std::runtime_error(what + " (sss_status=0x" + hex(st) + ")"),
          status_(st) {}

    /** @return The raw SSS status code. */
    sss_status_t status() const { return status_; }

private:
    static std::string hex(sss_status_t st);
    sss_status_t status_;
};

/** @brief RSA key size in bits. */
enum class RsaBits { Rsa2048 = 2048, Rsa3072 = 3072, Rsa4096 = 4096 };

/**
 * @brief Throw CryptoError if @p st != kStatus_SSS_Success.
 * @param st    Status returned by an SSS call.
 * @param where Short identifier of the call site (embedded in the message).
 */
void check(sss_status_t st, const char *where);

/**
 * @brief Erase a persisted key object from the SE.
 *
 * Throws CryptoError if the object does not exist.
 *
 * @param s     Active session.
 * @param keyId SE object ID to erase.
 */
void eraseKey(class Session &s, uint32_t keyId);

/**
 * @brief RAII borrower of an already-opened SSS boot context.
 *
 * The boot framework (ex_sss_boot_open / ex_sss_session_close) owns the
 * real connection lifecycle; Session merely holds a non-owning pointer and
 * provides typed accessors so other classes do not touch ex_sss_boot_ctx_t
 * directly.
 *
 * Single responsibility: gateway from C++ code to the SSS C API session,
 * keystore and raw context without managing open/close itself.
 */
class Session {
public:
    /** @param ctx Already-open boot context (caller owns lifetime). */
    explicit Session(ex_sss_boot_ctx_t *ctx) : ctx_(ctx) {}

    /** @return SSS session pointer for asymmetric / RNG contexts. */
    sss_session_t      *session()  { return &ctx_->session; }
    /** @return SSS key store pointer for key object operations. */
    sss_key_store_t    *keystore() { return &ctx_->ks; }

private:
    ex_sss_boot_ctx_t *ctx_;
};

/**
 * @brief Generate random bytes using the SE05x hardware TRNG.
 * @param s        Active session.
 * @param numBytes Number of random bytes to produce.
 * @return         Vector of @p numBytes random bytes.
 * @throws CryptoError on SE failure.
 */
std::vector<uint8_t> getRandom(Session &s, size_t numBytes);

/**
 * @brief Operations on a single RSA key pair stored in the SE05x.
 *
 * Single responsibility: provide sign, verify, encrypt, decrypt, and CSR
 * generation for one persisted RSA key object.  Does not manage sessions,
 * policies, or certificate storage - those belong to other classes.
 *
 * Key objects are persistent on the SE.  The destructor does NOT erase the
 * key from SE storage; use eraseKey() or the @c --force flag for that.
 *
 * Move-only (not copyable) to express sole ownership of the in-memory
 * sss_object_t handle.
 */
class RsaKey {
public:
    /**
     * @brief Generate a fresh RSA key pair on the SE and persist it.
     * @param s     Active session.
     * @param keyId SE object ID to allocate.
     * @param bits  Key size.
     * @throws CryptoError on SE failure.
     */
    static RsaKey generate(Session &s, uint32_t keyId, RsaBits bits);

    /**
     * @brief Bind to an existing persisted RSA key object.
     * @param s     Active session.
     * @param keyId SE object ID of an existing RSA key pair.
     * @throws CryptoError if the object does not exist.
     */
    static RsaKey open(Session &s, uint32_t keyId);

    /**
     * @brief Sign a SHA-256 digest (RSASSA-PKCS1-v1_5).
     * @param digest 32-byte SHA-256 digest.
     * @return       Raw PKCS#1 v1.5 signature bytes.
     * @throws CryptoError on SE failure.
     */
    std::vector<uint8_t> sign(const std::vector<uint8_t> &digest);

    /**
     * @brief Verify a PKCS#1 v1.5 signature over a SHA-256 digest.
     * @param digest    32-byte SHA-256 digest.
     * @param signature Signature bytes.
     * @return          true if the signature is valid.
     */
    bool verify(const std::vector<uint8_t> &digest,
                const std::vector<uint8_t> &signature);

    /**
     * @brief Encrypt with RSAES-OAEP-SHA256.
     * @param plaintext Plaintext (max size ~ keySize/8 − 66 bytes for OAEP overhead).
     * @return          Ciphertext.
     * @throws CryptoError on SE failure or oversized input.
     */
    std::vector<uint8_t> encrypt(const std::vector<uint8_t> &plaintext);

    /**
     * @brief Decrypt with RSAES-OAEP-SHA256.
     * @param ciphertext Ciphertext produced by encrypt().
     * @return           Plaintext.
     * @throws CryptoError on SE failure.
     */
    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &ciphertext);

    /**
     * @brief Export the RSA public key as DER SubjectPublicKeyInfo.
     * @return SPKI DER bytes.
     * @throws CryptoError on SE failure.
     */
    std::vector<uint8_t> publicKeyDer();

    /**
     * @brief Generate a PKCS#10 CSR signed by the SE (key never exported).
     * @param subjectDn RFC 4514 distinguished name, e.g. "CN=device,O=Acme".
     * @return          PEM-encoded certificate signing request.
     * @throws CryptoError on SE or ASN.1 assembly failure.
     */
    std::string makeCsr(const std::string &subjectDn);

    ~RsaKey();
    RsaKey(RsaKey &&) noexcept;
    RsaKey &operator=(RsaKey &&) = delete;
    RsaKey(const RsaKey &) = delete;
    RsaKey &operator=(const RsaKey &) = delete;

private:
    RsaKey(Session &s) : s_(s) {}
    Session     &s_;
    sss_object_t obj_{};
    size_t       bits_ = 2048;
    bool         owns_ = false;  ///< false when opened (not generated) - no erase on close
};

/**
 * @brief Build a PKCS#10 CSR where signing is done externally (e.g. PKCS#11).
 *
 * Unlike RsaKey::makeCsr(), this variant passes the full CRI bytes (not a
 * pre-computed digest) to the sign callback so the caller can use mechanisms
 * like CKM_SHA256_RSA_PKCS that perform their own hashing.
 *
 * @param subjectDn RFC 4514 DN string.
 * @param spki      DER SubjectPublicKeyInfo (from RsaKey::publicKeyDer()).
 * @param sign      Callback: takes CRI bytes, returns raw PKCS#1 v1.5 signature.
 * @return          PEM CSR.
 * @throws CryptoError on ASN.1 assembly failure.
 */
std::string makeCsrFullSign(
    const std::string &subjectDn,
    const std::vector<uint8_t> &spki,
    std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)> sign);

/**
 * @brief Convert a DER SubjectPublicKeyInfo to PEM.
 *
 * Wraps the DER bytes in base64 with the standard
 * @c "-----BEGIN PUBLIC KEY-----" / @c "-----END PUBLIC KEY-----" headers.
 * This is the format expected by OpenSSL, curl, nginx, and most CA portals.
 *
 * @param spkiDer  DER bytes from RsaKey::publicKeyDer() or ICryptoBackend::getSpki().
 * @return         PEM string (NUL-terminated, newline at end).
 */
std::string spkiToPem(const std::vector<uint8_t> &spkiDer);

} // namespace se05x

#endif // SE05X_CRYPTO_HPP
