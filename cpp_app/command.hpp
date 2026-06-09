/**
 * @file command.hpp
 * @brief Command abstraction for the SE05x CLI (Command pattern).
 *
 * Each CLI operation is a small Command with a single responsibility.  Adding a
 * new operation means adding a Command subclass and registering it - no existing
 * dispatch code changes (open/closed).  A Command also declares what kind of SE
 * session it needs, so session setup is driven by the command rather than by a
 * hard-coded special case in main().
 */

#pragma once
#include "se05x_api.hpp"

#include <map>
#include <string>
#include <vector>

/** @brief Parsed command line: positional tokens + --opt value/flag map. */
struct Args {
    std::string group;      ///< 1st positional (rng/se/rsa)
    std::string command;    ///< 2nd positional (uid/genkey/...)
    std::string positional; ///< 3rd positional (rng <nbytes>)
    std::map<std::string, std::string> opt;

    bool flag(const std::string &k) const { return opt.count(k) != 0; }
    std::string get(const std::string &k, const std::string &def = "") const {
        auto it = opt.find(k);
        return it == opt.end() ? def : it->second;
    }
};

/** @brief The kind of SE session a command requires. */
enum class SessionNeed {
    Crypto,     ///< via ICryptoBackend; may use PKCS#11 (--pkcs11) or SSS
    Management, ///< SSS session with the applet selected (never PKCS#11)
    Isd,        ///< SSS session with the applet NOT selected (PlatformSCP rotation)
};

class OutputWriter; // result/file emission (output.hpp)

/** @brief Everything a command needs to run; assembled by main() after session setup. */
struct CommandContext {
    se05x::Se05x &api;   ///< the unified API (crypto via SSS/PKCS#11 + SSS-only management)
    se05x::Session *isd; ///< non-null for Isd commands (applet NOT selected; rotation only)
    OutputWriter &out;   ///< result and file output

    /** @return the raw ISD session, or throw if this invocation has none. */
    se05x::Session &requireIsd() const;
};

/** @brief One CLI operation.  Stateless; holds no session or backend. */
class Command {
public:
    virtual ~Command() = default;

    virtual const char *group() const = 0; ///< "rng" / "se" / "rsa"
    virtual const char *name() const = 0;  ///< "uid" / "genkey" / ... ("" = group default)
    virtual const char *help() const = 0;  ///< one-line usage string
    virtual SessionNeed sessionNeed() const = 0;

    /** @brief Extra names this command also answers to (e.g. genkey -> provision). */
    virtual std::vector<const char *> aliases() const { return {}; }

    /** @brief Execute. @return process exit code (0 ok, 1 error, 2 check-failed). */
    virtual int run(CommandContext &ctx, const Args &a) const = 0;
};
