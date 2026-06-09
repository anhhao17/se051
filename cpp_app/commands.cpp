/**
 * @file commands.cpp
 * @brief Concrete CLI commands and the registry that owns them.
 *
 * Each command does one operation and declares the session it needs.  Crypto
 * operations go through ctx.crypto (PKCS#11 or SSS); SE-management operations
 * (uid, cert, binding) and rotation use ctx.requireMgmt().  Output goes through
 * ctx.out.  None of them parse argv or open sessions - that is main()'s job.
 */

#include "commands.hpp"
#include "output.hpp"
#include "log.hpp"

#include "scp03_keyfile.hpp"
#include "scp03_rotate.hpp"
#include "se05x_crypto.hpp"
#include "se05x_provision.hpp"
#include "keys.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>

// CommandContext helper (declared in command.hpp).
se05x::Session &CommandContext::requireMgmt() const {
    if (!mgmt)
        throw std::runtime_error("this command needs a direct SE session; omit --pkcs11 and set "
                                 "--port / $EX_SSS_BOOT_SSS_PORT");
    return *mgmt;
}

namespace {

uint32_t parseId(const Args &a, uint32_t defaultId) {
    const std::string s = a.get("--id");
    if (s.empty())
        return defaultId;
    return static_cast<uint32_t>(std::strtoul(s.c_str(), nullptr, 0));
}

se05x::RsaBits parseBits(const std::string &s) {
    if (s.empty() || s == "2048")
        return se05x::RsaBits::Rsa2048;
    if (s == "3072")
        return se05x::RsaBits::Rsa3072;
    if (s == "4096")
        return se05x::RsaBits::Rsa4096;
    throw std::runtime_error("unknown RSA size: " + s);
}

se05x::KeyPolicy parsePolicy(const std::string &s) {
    if (s.empty() || s == "full")
        return se05x::KeyPolicy::Full;
    if (s == "sign-only")
        return se05x::KeyPolicy::SignOnly;
    if (s == "sign-decrypt")
        return se05x::KeyPolicy::SignDecrypt;
    throw std::runtime_error("unknown policy: " + s + " (use: full, sign-only, sign-decrypt)");
}

std::array<uint8_t, 16> parseKey16(const Args &a, const char *opt) {
    std::string h = a.get(opt);
    if (h.size() != 32)
        throw std::runtime_error(std::string(opt) + " must be 32 hex chars (16 bytes)");
    std::array<uint8_t, 16> out{};
    for (int i = 0; i < 16; ++i) {
        unsigned b = 0;
        if (std::sscanf(h.c_str() + i * 2, "%02x", &b) != 1)
            throw std::runtime_error(std::string("invalid hex in ") + opt);
        out[i] = static_cast<uint8_t>(b);
    }
    return out;
}

// Resolve the DATA bytes for write-info / verify-info: --data <text> (UTF-8)
// or --data-hex <hex>.  Exactly one must be given.
std::vector<uint8_t> infoData(const Args &a) {
    const std::string text = a.get("--data");
    const std::string hex = a.get("--data-hex");
    if (text.empty() == hex.empty())
        throw std::runtime_error("provide exactly one of --data <text> or --data-hex <hex>");
    if (!text.empty())
        return {text.begin(), text.end()};
    if (hex.size() % 2)
        throw std::runtime_error("--data-hex must have an even number of hex digits");
    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        unsigned b = 0;
        if (std::sscanf(hex.c_str() + i * 2, "%02x", &b) != 1)
            throw std::runtime_error("--data-hex: invalid hex");
        out[i] = static_cast<uint8_t>(b);
    }
    return out;
}

// Render bytes as printable text if all-printable, else as hex.
std::string bytesToDisplay(const std::vector<uint8_t> &b) {
    bool printable = !b.empty();
    for (uint8_t c : b)
        if (!(c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c < 0x7f))) {
            printable = false;
            break;
        }
    if (printable)
        return std::string(b.begin(), b.end());
    std::string hex;
    char tmp[4];
    for (uint8_t c : b) {
        std::snprintf(tmp, sizeof(tmp), "%02x", c);
        hex += tmp;
    }
    return hex;
}

class RngCommand final : public Command {
public:
    const char *group() const override { return "rng"; }
    const char *name() const override { return ""; } // group default: `rng <nbytes>`
    const char *help() const override {
        return "rng <nbytes>            random bytes from the SE TRNG";
    }
    SessionNeed sessionNeed() const override { return SessionNeed::Crypto; }
    int run(CommandContext &ctx, const Args &a) const override {
        if (a.positional.empty())
            throw std::runtime_error("usage: rng <nbytes>");
        size_t n = std::strtoul(a.positional.c_str(), nullptr, 0);
        ctx.out.bytes(a, ctx.crypto.getRandom(n));
        return 0;
    }
};

class UidCommand final : public Command {
public:
    const char *group() const override { return "se"; }
    const char *name() const override { return "uid"; }
    const char *help() const override {
        return "se  uid                 read the 18-byte chip UID";
    }
    SessionNeed sessionNeed() const override { return SessionNeed::Management; }
    int run(CommandContext &ctx, const Args &) const override {
        auto uid = se05x::readUid(ctx.requireMgmt());
        Log::get().print("UID (%zu bytes): ", uid.size());
        Log::get().hex(uid);
        return 0;
    }
};

class RotateScp03Command final : public Command {
public:
    const char *group() const override { return "se"; }
    const char *name() const override { return "rotate-scp03"; }
    const char *help() const override {
        return "se  rotate-scp03        --enc/--mac/--dek <hex32> [--dry-run|--confirm] [--key-out "
               "<f>]";
    }
    SessionNeed sessionNeed() const override { return SessionNeed::Isd; }
    int run(CommandContext &ctx, const Args &a) const override {
        const bool dryRun = a.flag("--dry-run");
        if (!dryRun && !a.flag("--confirm"))
            throw std::runtime_error(
                "rotate-scp03 is IRREVERSIBLE; add --confirm to execute, or --dry-run to preview");

        se05x::Scp03KeySet keys{};
        auto enc = parseKey16(a, "--enc"), mac = parseKey16(a, "--mac"),
             dek = parseKey16(a, "--dek");
        std::memcpy(keys.enc, enc.data(), 16);
        std::memcpy(keys.mac, mac.data(), 16);
        std::memcpy(keys.dek, dek.data(), 16);

        se05x::rotateScp03(ctx.requireMgmt(), keys, dryRun);
        if (dryRun)
            return 0;

        // Persist the new keys so the next session can authenticate.
        std::string outPath = a.get("--key-out");
        if (outPath.empty()) {
            const char *env = std::getenv("EX_SSS_BOOT_SCP03_PATH");
            if (env)
                outPath = env;
        }
        if (outPath.empty()) {
            LOG_ERROR("rotation succeeded but no key file to update (set "
                      "$EX_SSS_BOOT_SCP03_PATH or --key-out). New keys:\n");
            Log::get().print("ENC %s\nMAC %s\nDEK %s\n", a.get("--enc").c_str(),
                             a.get("--mac").c_str(), a.get("--dek").c_str());
            return 1;
        }
        try {
            se05x::Scp03KeyFile::write(outPath, keys); // backs up to <path>.bak
            LOG_OK("new SCP03 keys written to %s (previous keys saved to %s.bak)\n",
                   outPath.c_str(), outPath.c_str());
        } catch (const std::exception &e) {
            LOG_ERROR("rotation succeeded but writing %s failed: %s\n", outPath.c_str(), e.what());
            LOG_ERROR("RECORD THESE NEW KEYS IMMEDIATELY:\n");
            Log::get().print("ENC %s\nMAC %s\nDEK %s\n", a.get("--enc").c_str(),
                             a.get("--mac").c_str(), a.get("--dek").c_str());
            return 1;
        }
        return 0;
    }
};

class WriteInfoCommand final : public Command {
public:
    const char *group() const override { return "se"; }
    const char *name() const override { return "write-info"; }
    const char *help() const override {
        return "se  write-info         (--data <text> | --data-hex <hex>) [--id <hex>=0xFE000010] "
               "[--force]";
    }
    SessionNeed sessionNeed() const override { return SessionNeed::Management; }
    int run(CommandContext &ctx, const Args &a) const override {
        const uint32_t id = parseId(a, kDeviceInfoId);
        auto data = infoData(a);
        const bool force = a.flag("--force");
        bool wrote = se05x::writeBinary(ctx.requireMgmt(), id, data, force);
        if (wrote)
            LOG_OK("wrote %zu bytes to 0x%08X\n", data.size(), id);
        else
            LOG_INFO("0x%08X already exists; skipped (use --force to overwrite)\n", id);
        return 0;
    }
};

class ReadInfoCommand final : public Command {
public:
    const char *group() const override { return "se"; }
    const char *name() const override { return "read-info"; }
    const char *help() const override {
        return "se  read-info          [--id <hex>=0xFE000010] [--out <f>]";
    }
    SessionNeed sessionNeed() const override { return SessionNeed::Management; }
    int run(CommandContext &ctx, const Args &a) const override {
        auto data = se05x::readBinary(ctx.requireMgmt(), parseId(a, kDeviceInfoId));
        if (!a.get("--out").empty()) {
            ctx.out.bytes(a, data); // write raw bytes to file
        } else {
            ctx.out.line("%s\n", bytesToDisplay(data).c_str());
        }
        return 0;
    }
};

// Read KEY_ID and compare to the supplied DATA; print PASS/FAIL.
class VerifyInfoCommand final : public Command {
public:
    const char *group() const override { return "se"; }
    const char *name() const override { return "verify-info"; }
    const char *help() const override {
        return "se  verify-info        (--data <text> | --data-hex <hex>) [--id <hex>=0xFE000010]";
    }
    SessionNeed sessionNeed() const override { return SessionNeed::Management; }
    int run(CommandContext &ctx, const Args &a) const override {
        const uint32_t id = parseId(a, kDeviceInfoId);
        auto expected = infoData(a);
        auto actual = se05x::readBinary(ctx.requireMgmt(), id);
        bool ok = (actual == expected);
        ctx.out.line("%s\n", ok ? "PASS" : "FAIL");
        if (!ok)
            LOG_INFO("verify-info: 0x%08X has %zu bytes, expected %zu\n", id, actual.size(),
                     expected.size());
        return ok ? 0 : 2;
    }
};

class GenkeyCommand final : public Command {
public:
    const char *group() const override { return "rsa"; }
    const char *name() const override { return "genkey"; }
    std::vector<const char *> aliases() const override { return {"provision"}; }
    const char *help() const override {
        return "rsa genkey             [--id <hex>] [--bits 2048|3072|4096] [--policy ...] "
               "[--force] [--out <f>]";
    }
    SessionNeed sessionNeed() const override { return SessionNeed::Crypto; }
    int run(CommandContext &ctx, const Args &a) const override {
        uint32_t id = parseId(a, kRsaKeyId);
        se05x::RsaBits bits = parseBits(a.get("--bits"));
        se05x::KeyPolicy policy = parsePolicy(a.get("--policy"));

        if (policy != se05x::KeyPolicy::Full && a.flag("--pkcs11"))
            LOG_INFO("--policy is ignored with --pkcs11 (PKCS#11 keygen has no SSS policy)\n");

        if (ctx.crypto.keyExists(id)) {
            if (!a.flag("--force")) {
                LOG_INFO("RSA key 0x%08X already exists (use --force to regenerate)\n", id);
                if (!a.get("--out").empty())
                    ctx.out.spki(a, ctx.crypto.getSpki(id));
                return 0;
            }
            ctx.crypto.deleteKey(id);
        }
        LOG_INFO("RSA-%zu keygen on 0x%08X (~2-4 s)...\n", static_cast<size_t>(bits), id);
        ctx.crypto.generateKey(id, bits, policy);
        LOG_OK("RSA key provisioned\n");
        if (!a.get("--out").empty())
            ctx.out.spki(a, ctx.crypto.getSpki(id));
        return 0;
    }
};

class PubCommand final : public Command {
public:
    const char *group() const override { return "rsa"; }
    const char *name() const override { return "pub"; }
    const char *help() const override {
        return "rsa pub                [--id <hex>] [--out <f>] [--pem]";
    }
    SessionNeed sessionNeed() const override { return SessionNeed::Crypto; }
    int run(CommandContext &ctx, const Args &a) const override {
        ctx.out.spki(a, ctx.crypto.getSpki(parseId(a, kRsaKeyId)));
        return 0;
    }
};

class SignCommand final : public Command {
public:
    const char *group() const override { return "rsa"; }
    const char *name() const override { return "sign"; }
    const char *help() const override {
        return "rsa sign               [--id <hex>] --in <f> [--out <f>]";
    }
    SessionNeed sessionNeed() const override { return SessionNeed::Crypto; }
    int run(CommandContext &ctx, const Args &a) const override {
        ctx.out.bytes(
            a, ctx.crypto.sign(parseId(a, kRsaKeyId), OutputWriter::readFile(a.get("--in"))));
        return 0;
    }
};

class VerifyCommand final : public Command {
public:
    const char *group() const override { return "rsa"; }
    const char *name() const override { return "verify"; }
    const char *help() const override {
        return "rsa verify             [--id <hex>] --in <f> --sig <f>";
    }
    SessionNeed sessionNeed() const override { return SessionNeed::Crypto; }
    int run(CommandContext &ctx, const Args &a) const override {
        bool ok = ctx.crypto.verify(parseId(a, kRsaKeyId), OutputWriter::readFile(a.get("--in")),
                                    OutputWriter::readFile(a.get("--sig")));
        ctx.out.line("%s\n", ok ? "VERIFY OK" : "VERIFY FAILED");
        return ok ? 0 : 2;
    }
};

class CsrCommand final : public Command {
public:
    const char *group() const override { return "rsa"; }
    const char *name() const override { return "csr"; }
    const char *help() const override {
        return "rsa csr                [--id <hex>] --subject \"CN=...\" [--out <f>]";
    }
    SessionNeed sessionNeed() const override { return SessionNeed::Crypto; }
    int run(CommandContext &ctx, const Args &a) const override {
        const auto dn = a.get("--subject");
        if (dn.empty())
            throw std::runtime_error("--subject is required");
        ctx.out.text(a, ctx.crypto.makeCsr(parseId(a, kRsaKeyId), dn));
        return 0;
    }
};

class WriteCertCommand final : public Command {
public:
    const char *group() const override { return "rsa"; }
    const char *name() const override { return "write-cert"; }
    const char *help() const override {
        return "rsa write-cert         [--id <hex>] --in <cert.der>   (SSS only)";
    }
    SessionNeed sessionNeed() const override { return SessionNeed::Management; }
    int run(CommandContext &ctx, const Args &a) const override {
        uint32_t id = parseId(a, kRsaCerId);
        auto der = OutputWriter::readFile(a.get("--in"));
        se05x::writeCert(ctx.requireMgmt(), id, der);
        LOG_OK("certificate written (id=0x%08X, %zu bytes)\n", id, der.size());
        return 0;
    }
};

class VerifyBindingCommand final : public Command {
public:
    const char *group() const override { return "rsa"; }
    const char *name() const override { return "verify-binding"; }
    const char *help() const override {
        return "rsa verify-binding     [--id <hex>=key] (--cert <cert.der> | --cert-id "
               "<hex>=0xF0000002) (SSS only)";
    }
    SessionNeed sessionNeed() const override { return SessionNeed::Management; }
    int run(CommandContext &ctx, const Args &a) const override {
        se05x::Session &s = ctx.requireMgmt();
        const uint32_t keyId = parseId(a, kRsaKeyId); // the SE key that signs

        std::vector<uint8_t> certDer;
        const std::string certPath = a.get("--cert");
        if (!certPath.empty()) {
            certDer = OutputWriter::readFile(certPath);
        } else {
            const std::string cidStr = a.get("--cert-id");
            uint32_t certId = cidStr.empty()
                                  ? kRsaCerId
                                  : static_cast<uint32_t>(std::strtoul(cidStr.c_str(), nullptr, 0));
            LOG_INFO("reading stored certificate from 0x%08X\n", certId);
            certDer = se05x::readBinary(s, certId);
        }

        bool ok = se05x::verifyBindingRsa(s, keyId, certDer);
        ctx.out.line("%s\n", ok ? "BINDING OK" : "BINDING FAILED");
        return ok ? 0 : 2;
    }
};

} // namespace

void CommandRegistry::add(std::unique_ptr<Command> c) {
    const Command *p = c.get();
    index_[{p->group(), p->name()}] = p;
    for (const char *alias : p->aliases())
        index_[{p->group(), alias}] = p;
    cmds_.push_back(std::move(c));
}

CommandRegistry::CommandRegistry() {
    add(std::make_unique<RngCommand>());
    add(std::make_unique<UidCommand>());
    add(std::make_unique<RotateScp03Command>());
    add(std::make_unique<WriteInfoCommand>());
    add(std::make_unique<ReadInfoCommand>());
    add(std::make_unique<VerifyInfoCommand>());
    add(std::make_unique<GenkeyCommand>());
    add(std::make_unique<PubCommand>());
    add(std::make_unique<SignCommand>());
    add(std::make_unique<VerifyCommand>());
    add(std::make_unique<CsrCommand>());
    add(std::make_unique<WriteCertCommand>());
    add(std::make_unique<VerifyBindingCommand>());
}

const Command *CommandRegistry::find(const std::string &group, const std::string &command) const {
    auto it = index_.find({group, command});
    if (it != index_.end())
        return it->second;
    // Fall back to a group's default (positional) command, e.g. `rng 16`.
    auto def = index_.find({group, ""});
    if (def != index_.end())
        return def->second;
    return nullptr;
}

void CommandRegistry::usage(const char *prog) const {
    std::fprintf(stderr,
                 "Usage: %s [--pkcs11 <lib>] [--port <conn>] [--log <file>] [--debug] <group> "
                 "<command> [options]\n\nCommands:\n",
                 prog);
    for (const auto &c : cmds_)
        std::fprintf(stderr, "  %s\n", c->help());
    std::fprintf(stderr,
                 "\n--pkcs11  Route crypto through the PKCS#11 module; without it, SSS + mbedTLS\n"
                 "          are used directly.  uid / write-cert / verify-binding / rotate-scp03\n"
                 "          always use SSS.\n"
                 "--debug / --verbose  enable detailed (DEBUG-level) logging for diagnosis.\n"
                 "--log <file>         also write the log to <file>.\n"
                 "Connect string via --port or $EX_SSS_BOOT_SSS_PORT.\n");
}
