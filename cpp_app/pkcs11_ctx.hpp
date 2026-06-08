/**
 * @file pkcs11_ctx.hpp
 * @brief RAII C++ wrapper for the NXP SE05x PKCS#11 module loaded via dlopen.
 *
 * Responsibilities of Pkcs11Ctx:
 *   - Library lifecycle  : dlopen → C_Initialize → OpenSession on construction;
 *                          CloseSession → C_Finalize → dlclose on destruction.
 *   - Key generation     : genRsaKeyPair() creates persistent SE token objects.
 *   - Key lookup         : findKey() locates objects by their SE object-ID label.
 *   - Crypto operations  : sign, verify, encrypt, decrypt (RSA only).
 *   - RNG                : getRandom() via C_GenerateRandom.
 *
 * All operations throw Pkcs11Error on failure.
 *
 * Key label convention:
 *   NXP SE05x PKCS#11 maps the label @c "sss:0xXXXXXXXX" to the SE object ID
 *   @c 0xXXXXXXXX.  Use Pkcs11Ctx::label() to format an ID.
 *
 * Signature format note:
 *   signRsa()  uses CKM_SHA256_RSA_PKCS — the SE performs SHA-256 hashing
 *   internally.  The returned bytes are a raw PKCS#1 v1.5 RSA signature.
 *   verifyRsa() expects the same format.
 *   This means sign() / verify() both take the *full message*, not a digest.
 */

#pragma once

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

extern "C" {
#include "cryptoki.h"
}

/**
 * @brief Exception thrown on any PKCS#11 API failure.
 *
 * Carries the raw CK_RV return value alongside the human-readable message.
 */
class Pkcs11Error : public std::runtime_error {
public:
    /**
     * @param msg  Human-readable description of the failure.
     * @param rv   CK_RV return value from the failing call (default: CKR_GENERAL_ERROR).
     */
    explicit Pkcs11Error(const std::string &msg,
                         CK_RV rv = CKR_GENERAL_ERROR);

    /** @return The CK_RV code that triggered this exception. */
    CK_RV rv() const { return rv_; }

private:
    CK_RV rv_;
};

/**
 * @brief RAII PKCS#11 session over the NXP SE05x runtime library.
 *
 * One instance represents one open read-write session on the first token slot
 * returned by the library.  Not copyable; unique ownership of the session.
 *
 * Typical usage:
 * @code
 *   Pkcs11Ctx p11("/path/to/libsss_pkcs11.so");
 *   auto [hPub, hPriv] = p11.genRsaKeyPair(0xEF000001, 2048);
 *   auto sig = p11.signRsa(hPriv, message);
 * @endcode
 */
class Pkcs11Ctx {
public:
    /**
     * @brief Load the PKCS#11 library and open a session.
     *
     * @param libPath  Full path to @c libsss_pkcs11.so (or its symlink).
     * @throws Pkcs11Error if the library cannot be loaded, initialized, or
     *                     if no token slot is present.
     */
    explicit Pkcs11Ctx(const std::string &libPath);

    /**
     * @brief Close session, finalize and unload the library.
     */
    ~Pkcs11Ctx();

    Pkcs11Ctx(const Pkcs11Ctx &) = delete;
    Pkcs11Ctx &operator=(const Pkcs11Ctx &) = delete;

    /**
     * @brief Generate a persistent RSA key pair on the SE.
     *
     * The key pair is stored as a token object under the label produced by
     * label(@p id).  The SE object ID in the SE05x keystore is @p id.
     *
     * @param id    SE05x object ID (determines label and CKA_ID).
     * @param bits  RSA key size in bits (e.g. 2048).
     * @return      Pair of {public-key handle, private-key handle}.
     * @throws Pkcs11Error on SE or PKCS#11 failure.
     */
    std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE>
    genRsaKeyPair(uint32_t id, CK_ULONG bits);

    /**
     * @brief Find a key object by SE object ID and PKCS#11 key class.
     *
     * Searches by the label @c "sss:0xXXXXXXXX".
     *
     * @param id   SE05x object ID.
     * @param cls  CKO_PUBLIC_KEY or CKO_PRIVATE_KEY.
     * @return     Object handle, or CK_INVALID_HANDLE if not found.
     */
    CK_OBJECT_HANDLE findKey(uint32_t id, CK_OBJECT_CLASS cls);

    /**
     * @brief Destroy a PKCS#11 object (removes from SE storage).
     * @param h  Handle returned by genRsaKeyPair() or findKey().
     */
    void destroyObject(CK_OBJECT_HANDLE h);

    /**
     * @brief Export the RSA public key at @p id as SubjectPublicKeyInfo DER.
     *
     * Reads CKA_MODULUS and CKA_PUBLIC_EXPONENT from the public-key object and
     * constructs the SPKI encoding with mbedTLS.  Use this instead of opening a
     * parallel SSS session (which would reset the PKCS#11 SCP03 channel).
     *
     * @param id  SE05x object ID.
     * @return    SPKI DER bytes (suitable for CSR subjectPublicKeyInfo).
     * @throws Pkcs11Error if the key is not found or attribute read fails.
     */
    std::vector<uint8_t> getSpki(uint32_t id);


    /**
     * @brief Sign a message with RSA PKCS#1 v1.5 / SHA-256.
     *
     * Uses CKM_SHA256_RSA_PKCS; the SE performs SHA-256 hashing internally.
     * Pass the *full message*, not a pre-hashed digest.
     *
     * @param hPriv  Private-key handle.
     * @param msg    Arbitrary-length message bytes.
     * @return       Raw PKCS#1 v1.5 signature (keySize/8 bytes).
     * @throws Pkcs11Error on failure.
     */
    std::vector<uint8_t> signRsa(CK_OBJECT_HANDLE hPriv,
                                 const std::vector<uint8_t> &msg);

    /**
     * @brief Verify an RSA PKCS#1 v1.5 / SHA-256 signature.
     *
     * Uses CKM_SHA256_RSA_PKCS; pass the *full message*, not a digest.
     *
     * @param hPub  Public-key handle.
     * @param msg   Original message.
     * @param sig   Signature produced by signRsa().
     * @return      true if valid, false otherwise (no exception on mismatch).
     */
    bool verifyRsa(CK_OBJECT_HANDLE hPub,
                   const std::vector<uint8_t> &msg,
                   const std::vector<uint8_t> &sig);

    /**
     * @brief Encrypt with RSA-OAEP-SHA256 (CKM_RSA_PKCS_OAEP).
     *
     * @param hPub   Public-key handle.
     * @param plain  Plaintext (max ~keySize/8 − 66 bytes).
     * @return       Ciphertext.
     * @throws Pkcs11Error on failure or oversized input.
     */
    std::vector<uint8_t> encryptRsa(CK_OBJECT_HANDLE hPub,
                                    const std::vector<uint8_t> &plain);

    /**
     * @brief Decrypt with RSA-OAEP-SHA256 (CKM_RSA_PKCS_OAEP).
     *
     * @param hPriv  Private-key handle.
     * @param cipher Ciphertext from encryptRsa().
     * @return       Plaintext.
     * @throws Pkcs11Error on failure.
     */
    std::vector<uint8_t> decryptRsa(CK_OBJECT_HANDLE hPriv,
                                    const std::vector<uint8_t> &cipher);

    /**
     * @brief Generate random bytes via the SE hardware TRNG.
     * @param n  Number of bytes to produce.
     * @return   Vector of @p n random bytes.
     * @throws Pkcs11Error on failure.
     */
    std::vector<uint8_t> getRandom(size_t n);

private:
    static std::string           label(uint32_t id);
    static std::array<CK_BYTE, 4> idBytes(uint32_t id);


    void                *lib_   = nullptr;
    CK_FUNCTION_LIST_PTR p11_   = nullptr;
    CK_SESSION_HANDLE    hSess_ = CK_INVALID_HANDLE;
};
