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
#include "crypto_backend.hpp"
#include "log.hpp"
#include "output.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

extern "C" {
#include <ex_sss_boot.h>
#include <fsl_sss_api.h>
}

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

    ex_sss_boot_ctx_t ctx{};
    bool sssOpened = false;
    std::unique_ptr<se05x::Session> session;
    std::unique_ptr<ICryptoBackend> backend;
    OutputWriter out;

    if (usePkcs11) {
        try {
            backend = std::make_unique<Pkcs11Backend>(pkcs11Lib);
        } catch (const std::exception &e) {
            LOG_ERROR("PKCS#11 init failed: %s\n", e.what());
            return 1;
        }
    } else {
        // Rotation targets the ISD; everything else uses the applet.
        if (need == SessionNeed::Isd)
            ctx.se05x_open_ctx.skip_select_applet = 1;

        sss_status_t st = ex_sss_boot_open(&ctx, portName);
        if (st != kStatus_SSS_Success) {
            LOG_ERROR("ex_sss_boot_open failed (0x%04x) - set --port or "
                      "$EX_SSS_BOOT_SSS_PORT\n",
                      static_cast<unsigned>(st));
            return 1;
        }
        st = ex_sss_key_store_and_object_init(&ctx);
        if (st != kStatus_SSS_Success) {
            LOG_ERROR("key store init failed (0x%04x)\n", static_cast<unsigned>(st));
            ex_sss_session_close(&ctx);
            return 1;
        }
        sssOpened = true;
        session = std::make_unique<se05x::Session>(&ctx);
        backend = std::make_unique<SssBackend>(*session);
    }

    CommandContext cctx{*backend, session.get(), out};
    int rc = 0;
    try {
        rc = cmd->run(cctx, a);
    } catch (const std::exception &e) {
        LOG_ERROR("command '%s %s' failed: %s\n", a.group.c_str(), a.command.c_str(), e.what());
        rc = 1;
    }

    if (sssOpened)
        ex_sss_session_close(&ctx);
    return rc;
}
