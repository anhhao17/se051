/**
 * @file se05x_api.hpp
 * @brief API layer: the single public surface for the SE05x.
 *
 * Se05x is what both the CLI and external integrators call.  It owns no SSS or
 * PKCS#11 state - it routes:
 *
 *   - crypto ops      -> an ICryptoBackend (SSS or PKCS#11)
 *   - management ops  -> an SssBackend (SSS only; throws if absent)
 *
 * Construct with the crypto backend in use and, when on the SSS path, a pointer
 * to that same SssBackend for the management operations:
 *
 *     SssBackend sss(session);
 *     se05x::Se05x api(sss, &sss);          // full feature set
 *
 *     Pkcs11Backend p11(libPath);
 *     se05x::Se05x api(p11);                 // crypto only; management throws
 */

#ifndef SE05X_API_HPP
#define SE05X_API_HPP

#include "crypto.hpp"
#include "sss.hpp"

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace se05x {

/** @brief The SE05x integration facade (CLI + external services). */
class Se05x {
public:
    /**
     * @param crypto Crypto backend (SSS or PKCS#11).
     * @param mgmt   SSS backend for management ops, or nullptr (PKCS#11 path).
     */
    explicit Se05x(ICryptoBackend &crypto, SssBackend *mgmt = nullptr)
        : crypto_(crypto), mgmt_(mgmt) {}

    // --- Crypto (SSS or PKCS#11) ---

    std::vector<uint8_t> randomBytes(size_t n) { return crypto_.getRandom(n); }
    bool keyExists(uint32_t id) { return crypto_.keyExists(id); }
    void deleteKey(uint32_t id) { crypto_.deleteKey(id); }
    void generateKey(uint32_t id, RsaBits bits, KeyPolicy policy = KeyPolicy::Full) {
        crypto_.generateKey(id, bits, policy);
    }
    std::vector<uint8_t> publicKeyDer(uint32_t id) { return crypto_.getSpki(id); }
    std::string publicKeyPem(uint32_t id) { return spkiToPem(crypto_.getSpki(id)); }
    std::vector<uint8_t> signMessage(uint32_t id, const std::vector<uint8_t> &msg) {
        return crypto_.sign(id, msg);
    }
    bool verifyMessage(uint32_t id, const std::vector<uint8_t> &msg,
                       const std::vector<uint8_t> &sig) {
        return crypto_.verify(id, msg, sig);
    }
    std::string makeCsr(uint32_t id, const std::string &subjectDn) {
        return crypto_.makeCsr(id, subjectDn);
    }

    // --- Management (SSS only) ---

    std::vector<uint8_t> uid() { return mgmt().uid(); }
    void writeCert(uint32_t id, const std::vector<uint8_t> &der) { mgmt().writeCert(id, der); }
    bool writeBinary(uint32_t id, const std::vector<uint8_t> &data, bool force) {
        return mgmt().writeBinary(id, data, force);
    }
    std::vector<uint8_t> readBinary(uint32_t id) { return mgmt().readBinary(id); }
    bool verifyBinding(uint32_t id, const std::vector<uint8_t> &certDer) {
        return mgmt().verifyBinding(id, certDer);
    }

private:
    SssBackend &mgmt() {
        if (!mgmt_)
            throw std::runtime_error("this operation needs a direct SE session (SSS); "
                                     "it is not available over --pkcs11");
        return *mgmt_;
    }

    ICryptoBackend &crypto_;
    SssBackend *mgmt_;
};

/**
 * @brief One-call setup that owns a complete SE05x stack and exposes its Se05x.
 *
 * This is the entry point for external integrators: pick a transport and get a
 * ready-to-use API, with the connection, backend and facade all owned and torn
 * down together.  No CLI concepts (commands, session routing) are involved.
 *
 *     auto dev = se05x::Se05xClient::openSss("/dev/i2c-1:0x48");
 *     auto uid = dev->api().uid();
 *     dev->api().generateKey(0xFE000001, se05x::RsaBits::Rsa2048);
 *
 *     auto dev = se05x::Se05xClient::openPkcs11("/usr/lib/libsss_pkcs11.so");
 *     auto sig = dev->api().signMessage(0xFE000001, msg);  // management ops throw
 */
class Se05xClient {
public:
    /**
     * @brief Open over the NXP SSS API (full feature set: crypto + management).
     * @param port         Connect string, or nullptr for the middleware default.
     * @param selectApplet false only for the ISD channel (SCP03 rotation).
     * @throws CryptoError on failure.
     */
    static std::unique_ptr<Se05xClient> openSss(const char *port, bool selectApplet = true);

    /**
     * @brief Open over the PKCS#11 module (crypto only; management ops throw).
     * @throws Pkcs11Error on failure.
     */
    static std::unique_ptr<Se05xClient> openPkcs11(const char *libPath);

    /** @return The API surface to call. */
    Se05x &api() { return *api_; }

    /** @return The raw SSS session for advanced ops (SCP03 rotation), else nullptr. */
    Session *sssSession() { return conn_ ? &conn_->session() : nullptr; }

    ~Se05xClient();
    Se05xClient(const Se05xClient &) = delete;
    Se05xClient &operator=(const Se05xClient &) = delete;

private:
    Se05xClient() = default;

    std::unique_ptr<SssConnection> conn_;    ///< SSS path: owns the connection
    std::unique_ptr<SssBackend> sss_;        ///< SSS path: crypto + management backend
    std::unique_ptr<ICryptoBackend> crypto_; ///< PKCS#11 path: Pkcs11Backend
    std::unique_ptr<Se05x> api_;
};

} // namespace se05x

#endif // SE05X_API_HPP
