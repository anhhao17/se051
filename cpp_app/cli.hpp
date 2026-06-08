/**
 * @file cli.hpp
 * @brief Command-line interface parser and dispatcher for SE05x operations.
 *
 * Single responsibility: translate argv into ICryptoBackend / se05x API calls
 * and format results for the terminal.  Session and backend lifecycle are external.
 *
 * Cli holds:
 *   crypto_ — ICryptoBackend reference for all crypto operations (genkey, sign,
 *              verify, encrypt, decrypt, csr, rng, pub).  Caller supplies either
 *              a Pkcs11Backend or an SssBackend; Cli never checks which.
 *   mgmt_   — nullable se05x::Session* for management-only operations (se uid,
 *              rsa write-cert, rsa verify-binding) that have no PKCS#11 equivalent.
 */

#pragma once

#include "crypto_backend.hpp"
#include "log.hpp"

#include <map>
#include <string>
#include <vector>

/**
 * @brief CLI parser and dispatcher for SE05x RSA crypto and provisioning.
 *
 * Usage:
 * @code
 *   SssBackend backend(session);
 *   return Cli(backend, &session).run(argc, argv);
 * @endcode
 */
class Cli {
public:
    /**
     * @param crypto  Backend that handles all key and crypto operations.
     * @param log     Output sink (stdout or log file).
     * @param mgmt    SE session for management commands (uid / write-cert /
     *                verify-binding), or nullptr if not needed.
     */
    explicit Cli(ICryptoBackend &crypto, Log &log,
                 se05x::Session *mgmt = nullptr);

    /**
     * @brief Parse @p argv and dispatch to the appropriate command handler.
     * @return 0 on success, 1 on error, 2 when a verification check fails.
     */
    int run(int argc, char **argv);

    /**
     * @brief Print command usage to stderr.
     * @param prog  argv[0].
     */
    static void usage(const char *prog);

private:
    /** @brief Parsed command-line arguments. */
    struct Args {
        std::string group;       ///< First positional token (rng / se / rsa).
        std::string command;     ///< Second positional token (uid / genkey / sign …).
        std::string positional;  ///< Third positional token (used by rng for <nbytes>).
        std::map<std::string, std::string> opt;

        bool flag(const std::string &k) const { return opt.count(k) != 0; }
        std::string get(const std::string &k, const std::string &def = "") const {
            auto it = opt.find(k);
            return it == opt.end() ? def : it->second;
        }
    };

    static Args parse(int argc, char **argv);

    int doRng(const Args &a);
    int doSe(const Args &a);
    int doRsa(const Args &a);

    static std::vector<uint8_t> readFile(const std::string &path);
    static void writeFile(const std::string &path, const std::vector<uint8_t> &d);
    void emit(const Args &a, const std::vector<uint8_t> &d) const;
    void emitSpki(const Args &a, const std::vector<uint8_t> &spki) const;
    void emitText(const Args &a, const std::string &text) const;

    static uint32_t        parseId(const Args &a);
    static se05x::RsaBits  parseBits(const std::string &s);

    /** @brief Return the management session, or throw if not available. */
    se05x::Session &mgmt() const;

    ICryptoBackend  &crypto_;  ///< backend for all crypto operations
    Log             &log_;     ///< output sink (stdout or log file)
    se05x::Session  *mgmt_;    ///< nullable — null for pure-crypto invocations
};
