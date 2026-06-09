/**
 * @file sss.hpp
 * @brief SSS layer: the classes that hold the NXP SSS library interaction.
 *
 * This is the SSS half of the bottom layer (the PKCS#11 half is pkcs11_ctx.hpp).
 * Everything that touches the SSS C API lives here:
 *
 *   Low-level primitives:
 *     - CryptoError / check : SSS status handling.
 *     - Session             : non-owning gateway to an opened boot context.
 *     - KeyObject           : RAII over a single sss_object_t handle.
 *     - sha256 / spkiToPem / makeCsrFullSign : host-side crypto helpers.
 *     - RsaKey              : operations on one SE-resident RSA key.
 *
 *   SssBackend : the crypto-layer implementation (ICryptoBackend) PLUS the
 *                SSS-only management operations (uid, certificate/blob storage,
 *                key<->cert binding) that the PKCS#11 path cannot provide.
 *
 * All failures are reported by throwing CryptoError.
 */

#ifndef SSS_HPP
#define SSS_HPP

#include "crypto.hpp"

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
 * Carries the raw @c sss_status_t for callers that want to inspect the code.
 */
class CryptoError : public std::runtime_error {
public:
    explicit CryptoError(const std::string &what, sss_status_t st = kStatus_SSS_Fail)
        : std::runtime_error(what + " (sss_status=0x" + hex(st) + ")"), status_(st) {}

    sss_status_t status() const { return status_; }

private:
    static std::string hex(sss_status_t st);
    sss_status_t status_;
};

/** @brief Throw CryptoError if @p st != kStatus_SSS_Success. */
void check(sss_status_t st, const char *where);

/** @brief SHA-256 of @p in (mbedTLS, host-side). */
std::vector<uint8_t> sha256(const std::vector<uint8_t> &in);

/** @brief Convert a DER SubjectPublicKeyInfo to PEM. */
std::string spkiToPem(const std::vector<uint8_t> &spkiDer);

/**
 * @brief Build a PKCS#10 CSR where signing is done externally (e.g. PKCS#11).
 *
 * Passes the full CRI bytes (not a digest) to @p sign so the caller can use a
 * mechanism that hashes internally.
 *
 * @param subjectDn RFC 4514 DN string.
 * @param spki      DER SubjectPublicKeyInfo.
 * @param sign      Callback: CRI bytes -> raw PKCS#1 v1.5 signature.
 * @return          PEM CSR.
 */
std::string makeCsrFullSign(const std::string &subjectDn, const std::vector<uint8_t> &spki,
                            std::function<std::vector<uint8_t>(const std::vector<uint8_t> &)> sign);

/**
 * @brief RAII borrower of an already-opened SSS boot context.
 *
 * The boot framework owns the connection lifecycle; Session holds a non-owning
 * pointer and provides typed accessors so other code never touches
 * ex_sss_boot_ctx_t directly.
 */
class Session {
public:
    explicit Session(ex_sss_boot_ctx_t *ctx) : ctx_(ctx) {}

    sss_session_t *session() { return &ctx_->session; }
    sss_key_store_t *keystore() { return &ctx_->ks; }
    /** @return The underlying boot context (PlatformSCP03 / host-crypto access). */
    ex_sss_boot_ctx_t *bootCtx() { return ctx_; }

private:
    ex_sss_boot_ctx_t *ctx_;
};

/**
 * @brief Owns the SSS connection lifecycle - open + key-store init + close.
 *
 * The SSS analogue of Pkcs11Ctx: the only place that calls @c ex_sss_boot_open
 * / @c ex_sss_key_store_and_object_init / @c ex_sss_session_close.  Callers
 * (e.g. main) construct one of these and borrow its Session; they never touch
 * the SSS C lifecycle themselves.
 *
 * Non-copyable, non-movable (it owns the boot context the Session points into).
 */
class SssConnection {
public:
    /**
     * @param port         Connect string (e.g. "/dev/i2c-1:0x48"); nullptr uses
     *                     the middleware default.
     * @param selectApplet true for normal use; false for the ISD channel
     *                     (PlatformSCP03 rotation - applet deliberately not selected).
     * @throws CryptoError if the session or key store fails to open.
     */
    explicit SssConnection(const char *port, bool selectApplet = true);
    ~SssConnection();

    SssConnection(const SssConnection &) = delete;
    SssConnection &operator=(const SssConnection &) = delete;

    /** @return The borrowed Session for the crypto/management classes. */
    Session &session() { return session_; }

private:
    ex_sss_boot_ctx_t ctx_{};
    Session session_;
    bool opened_ = false;
};

/**
 * @brief RAII wrapper around a single @c sss_object_t handle.
 *
 * The one place that performs the SSS object-handle lifecycle (init /
 * get_handle / allocate_handle / free).  @c sss_key_object_free releases only
 * the host-side context - it does NOT erase the persisted SE object.
 *
 * Move-only.
 */
class KeyObject {
public:
    explicit KeyObject(Session &s) {
        check(sss_key_object_init(&obj_, s.keystore()), "key_object_init");
        live_ = true;
    }

    ~KeyObject() {
        if (live_)
            sss_key_object_free(&obj_);
    }

    KeyObject(KeyObject &&o) noexcept : obj_(o.obj_), live_(o.live_) { o.live_ = false; }
    KeyObject &operator=(KeyObject &&) = delete;
    KeyObject(const KeyObject &) = delete;
    KeyObject &operator=(const KeyObject &) = delete;

    /** @brief Bind to an existing object; false if absent (no throw). */
    bool bind(uint32_t id) { return sss_key_object_get_handle(&obj_, id) == kStatus_SSS_Success; }

    /** @brief Bind to an existing object, throwing if absent. */
    void open(uint32_t id, const char *where) {
        check(sss_key_object_get_handle(&obj_, id), where);
    }

    /** @brief Allocate a fresh persistent handle for a new object. */
    void allocate(uint32_t id, sss_key_part_t part, sss_cipher_type_t cipher, size_t byteLen,
                  const char *where) {
        check(sss_key_object_allocate_handle(&obj_, id, part, cipher,
                                             static_cast<uint32_t>(byteLen),
                                             kKeyObject_Mode_Persistent),
              where);
    }

    sss_object_t *raw() { return &obj_; }

private:
    sss_object_t obj_{};
    bool live_ = false; ///< false after a move - suppresses the free in the moved-from object
};

/**
 * @brief Operations on a single RSA key pair stored in the SE05x.
 *
 * Move-only.  The destructor does NOT erase the persisted key; use
 * SssBackend::deleteKey or @c --force for that.
 */
class RsaKey {
public:
    /** @brief Generate a fresh RSA key pair and persist it (optional policy). */
    static RsaKey generate(Session &s, uint32_t keyId, RsaBits bits,
                           sss_policy_t *policy = nullptr);

    /** @brief Bind to an existing persisted RSA key object. */
    static RsaKey open(Session &s, uint32_t keyId);

    /** @brief Sign a 32-byte SHA-256 digest (RSASSA-PKCS1-v1_5). */
    std::vector<uint8_t> sign(const std::vector<uint8_t> &digest);

    /** @brief Verify a PKCS#1 v1.5 signature over a SHA-256 digest. */
    bool verify(const std::vector<uint8_t> &digest, const std::vector<uint8_t> &signature);

    /** @brief Encrypt with RSAES-OAEP-SHA256. */
    std::vector<uint8_t> encrypt(const std::vector<uint8_t> &plaintext);

    /** @brief Decrypt with RSAES-OAEP-SHA256. */
    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &ciphertext);

    /** @brief Export the RSA public key as DER SubjectPublicKeyInfo. */
    std::vector<uint8_t> publicKeyDer();

    /** @brief Generate a PKCS#10 CSR signed by the SE (key never exported). */
    std::string makeCsr(const std::string &subjectDn);

    ~RsaKey();
    RsaKey(RsaKey &&) noexcept;
    RsaKey &operator=(RsaKey &&) = delete;
    RsaKey(const RsaKey &) = delete;
    RsaKey &operator=(const RsaKey &) = delete;

private:
    RsaKey(Session &s) : s_(s), obj_(s) {}
    Session &s_;
    KeyObject obj_;
    size_t bits_ = 2048;
    bool owns_ = false; ///< false when opened (not generated)
};

} // namespace se05x

/**
 * @brief SSS + mbedTLS backend - no PKCS#11 library required.
 *
 * Implements the crypto layer (ICryptoBackend) and additionally provides the
 * SSS-only management operations.  The se05x::Se05x API routes crypto calls
 * here (or to PKCS#11) and management calls here exclusively.
 *
 * @note The Session must outlive this object.
 */
class SssBackend final : public ICryptoBackend {
public:
    explicit SssBackend(se05x::Session &session) : s_(session) {}

    // --- ICryptoBackend (crypto) ---
    std::vector<uint8_t> getRandom(size_t n) override;
    bool keyExists(uint32_t id) override;
    void deleteKey(uint32_t id) override;
    void generateKey(uint32_t id, se05x::RsaBits bits,
                     se05x::KeyPolicy policy = se05x::KeyPolicy::Full) override;
    std::vector<uint8_t> getSpki(uint32_t id) override;
    std::vector<uint8_t> sign(uint32_t id, const std::vector<uint8_t> &msg) override;
    bool verify(uint32_t id, const std::vector<uint8_t> &msg,
                const std::vector<uint8_t> &sig) override;
    std::string makeCsr(uint32_t id, const std::string &subjectDn) override;

    // --- SSS-only management ---

    /** @brief Read the 18-byte chip UID. */
    std::vector<uint8_t> uid();

    /** @brief Store a DER certificate (idempotent erase-then-write). */
    void writeCert(uint32_t id, const std::vector<uint8_t> &der);

    /**
     * @brief Store a binary blob.
     * @return false (no-op) if it already exists and @p force is false.
     */
    bool writeBinary(uint32_t id, const std::vector<uint8_t> &data, bool force);

    /** @brief Read a binary object back. */
    std::vector<uint8_t> readBinary(uint32_t id);

    /** @brief Prove the SE key at @p id matches the public key in @p certDer. */
    bool verifyBinding(uint32_t id, const std::vector<uint8_t> &certDer);

private:
    bool objectExists(uint32_t id);
    void eraseObject(uint32_t id);
    void storeBinary(uint32_t id, const std::vector<uint8_t> &data, const char *tag);

    se05x::Session &s_;
};

#endif // SSS_HPP
