/**
 * @file main.cpp
 * @brief Entry point: parse argv, open the session the chosen command needs,
 *        then run the command.
 *
 * The SE05x supports only ONE Platform SCP03 channel at a time, so this opens
 * EITHER a PKCS#11 context OR an SSS session - never both.  Which one, and
 * whether the applet is selected, is driven entirely by the command's declared
 * SessionNeed (no per-command special-casing here):
 *
 *   Crypto      + --pkcs11  -> Pkcs11Backend (no SSS session)
 *   Crypto      (no pkcs11) -> SSS session, applet selected, SssBackend
 *   Management              -> SSS session, applet selected (uid/cert/binding)
 *   Isd                     -> SSS session, applet NOT selected (rotate-scp03)
 */

#include "cli.hpp"
#include "command.hpp"
#include "commands.hpp"
#include "log.hpp"
#include "output.hpp"
#include "se05x_api.hpp" // se05x::Se05xClient

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

namespace {
/** @brief Return the value following @p flag in argv, or nullptr. */
const char *argValue(int argc, char **argv, const char *flag) {
    for (int i = 1; i + 1 < argc; ++i)
        if (std::strcmp(argv[i], flag) == 0)
            return argv[i + 1];
    return nullptr;
}
bool hasFlag(int argc, char **argv, const char *flag) {
    for (int i = 1; i < argc; ++i)
        if (std::strcmp(argv[i], flag) == 0)
            return true;
    return false;
}
} // namespace

int main(int argc, char **argv) {
    if (argc < 2) {
        CommandRegistry().usage(argv[0]);
        return 1;
    }

    const char *logPath = argValue(argc, argv, "--log");
    const bool debug = hasFlag(argc, argv, "--debug") || hasFlag(argc, argv, "--verbose");
    try {
        Log::init(logPath, debug ? Log::DEBUG : Log::INFO);
    } catch (const std::exception &e) {
        std::fprintf(stderr, "[!] %s\n", e.what());
        return 1;
    }

    CommandRegistry registry;
    Args a = parseArgs(argc, argv);
    if (a.group.empty()) {
        registry.usage(argv[0]);
        return 1;
    }

    const Command *cmd = registry.find(a.group, a.command);
    if (!cmd) {
        registry.usage(argv[0]);
        LOG_ERROR("unknown command: %s %s\n", a.group.c_str(), a.command.c_str());
        return 1;
    }

    const char *portName = argValue(argc, argv, "--port");
    if (!portName)
        portName = std::getenv("EX_SSS_BOOT_SSS_PORT");
    const char *pkcs11Lib = argValue(argc, argv, "--pkcs11");

    const SessionNeed need = cmd->sessionNeed();
    const bool usePkcs11 = pkcs11Lib && need == SessionNeed::Crypto;

    LOG_DEBUG("dispatch: %s %s (session=%s)\n", a.group.c_str(), a.command.c_str(),
              usePkcs11 ? "PKCS#11"
                        : (need == SessionNeed::Isd ? "SSS/ISD (applet skipped)" : "SSS (applet)"));

    OutputWriter out;
    std::unique_ptr<se05x::Se05xClient> client;
    try {
        client = usePkcs11 ? se05x::Se05xClient::openPkcs11(pkcs11Lib)
                           : se05x::Se05xClient::openSss(portName, need != SessionNeed::Isd);
    } catch (const std::exception &e) {
        LOG_ERROR("session init failed: %s\n", e.what());
        return 1;
    }

    se05x::Session *isd = (need == SessionNeed::Isd) ? client->sssSession() : nullptr;
    CommandContext cctx{client->api(), isd, out};
    int rc = 0;
    try {
        rc = cmd->run(cctx, a);
    } catch (const std::exception &e) {
        LOG_ERROR("command '%s %s' failed: %s\n", a.group.c_str(), a.command.c_str(), e.what());
        rc = 1;
    }
    return rc; // SssConnection / Pkcs11Backend close their channels on destruction
}
