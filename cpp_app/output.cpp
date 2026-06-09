/**
 * @file output.cpp
 * @brief OutputWriter implementation.
 */

#include "output.hpp"
#include "command.hpp" // Args
#include "log.hpp"
#include "se05x_crypto.hpp" // se05x::spkiToPem

#include <cstdarg>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <stdexcept>

std::vector<uint8_t> OutputWriter::readFile(const std::string &path) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        throw std::runtime_error("cannot open: " + path);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

void OutputWriter::writeFile(const std::string &path, const std::vector<uint8_t> &d) {
    std::ofstream f(path, std::ios::binary);
    if (!f)
        throw std::runtime_error("cannot write: " + path);
    f.write(reinterpret_cast<const char *>(d.data()), static_cast<std::streamsize>(d.size()));
}

void OutputWriter::bytes(const Args &a, const std::vector<uint8_t> &d) const {
    const std::string out = a.get("--out");
    if (!out.empty()) {
        writeFile(out, d);
        LOG_OK("wrote %zu bytes to %s\n", d.size(), out.c_str());
    } else {
        Log::get().hex(d);
    }
}

void OutputWriter::spki(const Args &a, const std::vector<uint8_t> &spkiDer) const {
    if (a.flag("--pem"))
        text(a, se05x::spkiToPem(spkiDer));
    else
        bytes(a, spkiDer);
}

void OutputWriter::text(const Args &a, const std::string &t) const {
    const std::string out = a.get("--out");
    if (!out.empty()) {
        writeFile(out, {t.begin(), t.end()});
        LOG_OK("wrote %s\n", out.c_str());
    } else {
        Log::get().print("%s", t.c_str());
    }
}

void OutputWriter::line(const char *fmt, ...) const {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    Log::get().print("%s", buf);
}
