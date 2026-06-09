/**
 * @file cli.cpp
 * @brief Cli method implementations.
 *
 * All crypto commands delegate to ICryptoBackend — there is no backend-specific
 * branching here.  The caller (main.cpp) selects the concrete backend.
 *
 * SE management commands (se uid, rsa write-cert, rsa verify-binding) use the
 * management session directly; they are not available when --pkcs11 is passed
 * because a PKCS#11-only invocation does not open an SSS session.
 */

#include "cli.hpp"
#include "log.hpp"
#include "se05x_provision.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <stdexcept>

Cli::Cli(ICryptoBackend &crypto, se05x::Session *mgmt)
    : crypto_(crypto), mgmt_(mgmt) {}

se05x::Session &Cli::mgmt() const {
    if (!mgmt_)
        throw std::runtime_error(
            "this command requires a direct SE session; "
            "omit --pkcs11, or verify --port / $EX_SSS_BOOT_SSS_PORT");
    return *mgmt_;
}

int Cli::run(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 1; }
    Args a = parse(argc, argv);
    if (a.group.empty()) { usage(argv[0]); return 1; }

    if (a.group == "rng") return doRng(a);
    if (a.group == "se")  return doSe(a);
    if (a.group == "rsa") return doRsa(a);

    usage(argv[0]);
    return 1;
}

Cli::Args Cli::parse(int argc, char **argv) {
    Args a;
    std::vector<std::string> pos;
    for (int i = 1; i < argc; ++i) {
        std::string t = argv[i];
        if (t.rfind("--", 0) == 0) {
            if (t == "--force") { a.opt[t] = "1"; continue; }
            if (i + 1 < argc)  { a.opt[t] = argv[++i]; }
            else               { a.opt[t] = "1"; }
        } else {
            pos.push_back(t);
        }
    }
    if (pos.size() > 0) a.group      = pos[0];
    if (pos.size() > 1) a.command    = pos[1];
    if (pos.size() > 2) a.positional = pos[2];
    if (a.group == "rng" && a.positional.empty()) a.positional = a.command;
    return a;
}

void Cli::usage(const char *prog) {
    std::fprintf(stderr,
        "Usage: %s [--pkcs11 <lib>] [--port <conn>] [--log <file>] <group> <command> [options]\n\n"
        "Commands:\n"
        "  rng <nbytes>\n"
        "  se  uid\n"
        "  rsa genkey         [--id <hex>=0xFE000001] [--bits 2048|3072|4096] [--force] [--pem]\n"
        "  rsa pub            [--id <hex>=0xFE000001] [--out <file>] [--pem]\n"
        "  rsa sign           [--id <hex>=0xFE000001] --in <file>  [--out <file>]\n"
        "  rsa verify         [--id <hex>=0xFE000001] --in <file>  --sig <file>\n"
        "  rsa encrypt        [--id <hex>=0xFE000001] --in <file>  [--out <file>]\n"
        "  rsa decrypt        [--id <hex>=0xFE000001] --in <file>  [--out <file>]\n"
        "  rsa csr            [--id <hex>=0xFE000001] --subject \"CN=...,O=...\"\n"
        "  rsa write-cert     [--id <hex>=0xFE000001] --in <cert.der>   (SSS only)\n"
        "  rsa verify-binding [--id <hex>=0xFE000001] --cert <cert.der> (SSS only)\n\n"
        "--pkcs11  Route crypto through the PKCS#11 module (CKM_SHA256_RSA_PKCS,\n"
        "          CKM_RSA_PKCS_OAEP).  Without it, SSS + mbedTLS are used directly.\n"
        "          uid / write-cert / verify-binding always use SSS.\n\n"
        "Connect string via --port or $EX_SSS_BOOT_SSS_PORT.\n",
        prog);
}

std::vector<uint8_t> Cli::readFile(const std::string &path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open: " + path);
    return { std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>() };
}

void Cli::writeFile(const std::string &path, const std::vector<uint8_t> &d) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot write: " + path);
    f.write(reinterpret_cast<const char *>(d.data()),
            static_cast<std::streamsize>(d.size()));
}

void Cli::emit(const Args &a, const std::vector<uint8_t> &d) const {
    const std::string out = a.get("--out");
    if (!out.empty()) {
        writeFile(out, d);
        LOG_OK("wrote %zu bytes to %s\n", d.size(), out.c_str());
    } else {
        Log::get().hex(d);
    }
}

void Cli::emitSpki(const Args &a, const std::vector<uint8_t> &spki) const {
    if (a.flag("--pem"))
        emitText(a, se05x::spkiToPem(spki));
    else
        emit(a, spki);
}

void Cli::emitText(const Args &a, const std::string &text) const {
    const std::string out = a.get("--out");
    if (!out.empty()) {
        writeFile(out, { text.begin(), text.end() });
        LOG_OK("wrote %s\n", out.c_str());
    } else {
        Log::get().print("%s", text.c_str());
    }
}

uint32_t Cli::parseId(const Args &a) {
    const std::string s = a.get("--id");
    if (s.empty()) return 0xFE000001u;
    return static_cast<uint32_t>(std::strtoul(s.c_str(), nullptr, 0));
}

se05x::RsaBits Cli::parseBits(const std::string &s) {
    if (s.empty() || s == "2048") return se05x::RsaBits::Rsa2048;
    if (s == "3072")              return se05x::RsaBits::Rsa3072;
    if (s == "4096")              return se05x::RsaBits::Rsa4096;
    throw std::runtime_error("unknown RSA size: " + s);
}

int Cli::doRng(const Args &a) {
    if (a.positional.empty()) throw std::runtime_error("usage: rng <nbytes>");
    size_t n = std::strtoul(a.positional.c_str(), nullptr, 0);
    emit(a, crypto_.getRandom(n));
    return 0;
}

int Cli::doSe(const Args &a) {
    if (a.command == "uid") {
        auto uid = se05x::readUid(mgmt());
        Log::get().print("UID (%zu bytes): ", uid.size());
        Log::get().hex(uid);
        return 0;
    }
    throw std::runtime_error("unknown se command: " + a.command);
}

int Cli::doRsa(const Args &a) {
    const std::string &cmd = a.command;

    if (cmd == "genkey" || cmd == "provision") {
        uint32_t id         = parseId(a);
        se05x::RsaBits bits = parseBits(a.get("--bits"));

        if (crypto_.keyExists(id)) {
            if (!a.flag("--force")) {
                LOG_INFO("RSA key 0x%08X already exists (use --force to regenerate)\n", id);
                if (!a.get("--out").empty())
                    emitSpki(a, crypto_.getSpki(id));
                return 0;
            }
            crypto_.deleteKey(id);
        }
        LOG_INFO("RSA-%zu keygen on 0x%08X (~2-4 s)...\n",
                 static_cast<size_t>(bits), id);
        crypto_.generateKey(id, bits);
        LOG_OK("RSA key provisioned\n");
        if (!a.get("--out").empty())
            emitSpki(a, crypto_.getSpki(id));
        return 0;
    }

    if (cmd == "pub") {
        emitSpki(a, crypto_.getSpki(parseId(a)));
        return 0;
    }

    if (cmd == "sign") {
        emit(a, crypto_.sign(parseId(a), readFile(a.get("--in"))));
        return 0;
    }

    if (cmd == "verify") {
        uint32_t id = parseId(a);
        bool ok     = crypto_.verify(id, readFile(a.get("--in")),
                                         readFile(a.get("--sig")));
        Log::get().print("%s\n", ok ? "VERIFY OK" : "VERIFY FAILED");
        return ok ? 0 : 2;
    }

    if (cmd == "encrypt") {
        emit(a, crypto_.encrypt(parseId(a), readFile(a.get("--in"))));
        return 0;
    }

    if (cmd == "decrypt") {
        emit(a, crypto_.decrypt(parseId(a), readFile(a.get("--in"))));
        return 0;
    }

    if (cmd == "csr") {
        uint32_t id   = parseId(a);
        const auto dn = a.get("--subject");
        if (dn.empty()) throw std::runtime_error("--subject is required");
        emitText(a, crypto_.makeCsr(id, dn));
        return 0;
    }

    if (cmd == "write-cert") {
        uint32_t id = parseId(a);
        auto der    = readFile(a.get("--in"));
        se05x::writeCert(mgmt(), id, der);
        LOG_OK("certificate written (id=0x%08X, %zu bytes)\n", id, der.size());
        return 0;
    }

    if (cmd == "verify-binding") {
        const auto certPath = a.get("--cert");
        if (certPath.empty()) throw std::runtime_error("--cert is required");
        bool ok = se05x::verifyBindingRsa(mgmt(), parseId(a), readFile(certPath));
        Log::get().print("%s\n", ok ? "BINDING OK" : "BINDING FAILED");
        return ok ? 0 : 2;
    }

    throw std::runtime_error("unknown rsa command: " + cmd);
}
