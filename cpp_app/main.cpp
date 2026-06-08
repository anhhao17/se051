/**
 * @file main.cpp
 * @brief Entry point: construct the correct backend and run the CLI.
 *
 * SE05x supports only ONE Platform SCP03 channel at a time.  Opening both
 * ex_sss_boot (SSS) and PKCS#11 C_Initialize simultaneously resets whichever
 * channel was opened first, causing APDU errors (0x6982) on the stale session.
 *
 * Resolution: pre-parse the command group/name and open EITHER the SSS session
 * OR the PKCS#11 context — never both:
 *
 *   Pkcs11Backend  — rng, rsa genkey/pub/sign/verify/encrypt/decrypt/csr  (+--pkcs11)
 *   SssBackend     — everything else (se uid, rsa write-cert / verify-binding,
 *                    and any rsa command without --pkcs11)
 */

#include "cli.hpp"
#include "crypto_backend.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>

extern "C" {
#include <ex_sss_boot.h>
#include <fsl_sss_api.h>
}

namespace {

/** @brief Return the value of a named option from argv, or nullptr if absent. */
const char *argValue(int argc, char **argv, const char *flag) {
    for (int i = 1; i + 1 < argc; ++i)
        if (std::strcmp(argv[i], flag) == 0) return argv[i + 1];
    return nullptr;
}

struct PreParsed { std::string group, command; };

/** @brief Extract the first two positional tokens (group and command). */
PreParsed preParse(int argc, char **argv) {
    PreParsed r;
    for (int i = 1; i < argc; ++i) {
        std::string t = argv[i];
        if (t.rfind("--", 0) == 0) {
            if (t != "--force" && i + 1 < argc) ++i;
        } else {
            if (r.group.empty())        r.group   = t;
            else if (r.command.empty()) { r.command = t; break; }
        }
    }
    return r;
}

/**
 * @brief Return true when the command is handled entirely by PKCS#11 and must
 *        not open a parallel SSS session (which would reset the SCP03 channel).
 */
bool isPkcs11Command(const std::string &group, const std::string &cmd) {
    if (group == "rng") return true;
    if (group != "rsa") return false;
    static const std::array<const char *, 8> cmds = {{
        "genkey", "provision", "sign", "verify",
        "encrypt", "decrypt", "csr", "pub"
    }};
    for (const char *c : cmds)
        if (cmd == c) return true;
    return false;
}

} // namespace

int main(int argc, char **argv) {
    if (argc < 2) { Cli::usage(argv[0]); return 1; }

    const char *portEnv  = std::getenv("EX_SSS_BOOT_SSS_PORT");
    const char *portArg  = argValue(argc, argv, "--port");
    const char *portName = portArg ? portArg : portEnv;

    const char *pkcs11Lib = argValue(argc, argv, "--pkcs11");

    auto pre       = preParse(argc, argv);
    bool usePkcs11 = pkcs11Lib && isPkcs11Command(pre.group, pre.command);

    // ------------------------------------------------------------------
    // Open the appropriate backend (never both — SCP03 channel conflict).
    // ------------------------------------------------------------------

    ex_sss_boot_ctx_t ctx{};
    bool sssOpened = false;
    std::unique_ptr<se05x::Session>   session;
    std::unique_ptr<ICryptoBackend>   backend;

    if (usePkcs11) {
        try {
            backend = std::make_unique<Pkcs11Backend>(pkcs11Lib);
        } catch (const std::exception &e) {
            std::fprintf(stderr, "[!] PKCS#11 init failed: %s\n", e.what());
            return 1;
        }
    } else {
        sss_status_t st = ex_sss_boot_open(&ctx, portName);
        if (st != kStatus_SSS_Success) {
            std::fprintf(stderr,
                "[!] ex_sss_boot_open failed (0x%04x) — set --port or "
                "$EX_SSS_BOOT_SSS_PORT\n",
                static_cast<unsigned>(st));
            return 1;
        }
        st = ex_sss_key_store_and_object_init(&ctx);
        if (st != kStatus_SSS_Success) {
            std::fprintf(stderr, "[!] key store init failed (0x%04x)\n",
                         static_cast<unsigned>(st));
            ex_sss_session_close(&ctx);
            return 1;
        }
        sssOpened = true;
        session   = std::make_unique<se05x::Session>(&ctx);
        backend   = std::make_unique<SssBackend>(*session);
    }

    int rc = 0;
    try {
        rc = Cli(*backend, session.get()).run(argc, argv);
    } catch (const std::exception &e) {
        std::fprintf(stderr, "[!] %s\n", e.what());
        rc = 1;
    }

    if (sssOpened) ex_sss_session_close(&ctx);
    return rc;
}
