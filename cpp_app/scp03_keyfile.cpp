/**
 * @file scp03_keyfile.cpp
 * @brief SCP03 static-key file parsing and atomic write-back.
 */

#include "scp03_keyfile.hpp"

#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>

namespace se05x {
namespace Scp03KeyFile {

namespace {

// Parse exactly 16 hex byte-pairs from p into out; returns false on any
// non-hex / short read.
bool parse16(const char *p, uint8_t out[16]) {
    for (int i = 0; i < 16; ++i) {
        unsigned b = 0;
        if (std::sscanf(p + i * 2, "%02x", &b) != 1)
            return false;
        out[i] = static_cast<uint8_t>(b);
    }
    return true;
}

// Find tag ("ENC"/"MAC"/"DEK") in the file and copy its 16-byte value.
// Returns false if the tag line is absent or malformed.
bool findKey(const std::string &path, const char *tag, uint8_t out[16]) {
    FILE *fp = std::fopen(path.c_str(), "r");
    if (!fp)
        return false;

    char line[512];
    bool found = false;
    const size_t tagLen = std::strlen(tag);
    while (std::fgets(line, sizeof(line), fp)) {
        const char *p = line;
        while (*p == ' ' || *p == '\t')
            ++p;
        if (std::strncmp(p, tag, tagLen) != 0 || p[tagLen] != ' ')
            continue;
        p += tagLen + 1;
        while (*p == ' ' || *p == '\t')
            ++p;
        found = parse16(p, out);
        break;
    }
    std::fclose(fp);
    return found;
}

} // namespace

bool readDek(const std::string &path, uint8_t dek[16]) {
    return findKey(path, "DEK", dek);
}

Scp03KeySet read(const std::string &path) {
    Scp03KeySet ks{};
    if (!findKey(path, "ENC", ks.enc) || !findKey(path, "MAC", ks.mac) ||
        !findKey(path, "DEK", ks.dek))
        throw std::runtime_error(
            "Scp03KeyFile::read: '" + path +
            "' is missing or has a malformed ENC/MAC/DEK line (need 'TAG <32 hex>')");
    return ks;
}

void write(const std::string &path, const Scp03KeySet &keys) {
    // 1) Back up any existing file so the previous (recovery) keys survive.
    if (FILE *cur = std::fopen(path.c_str(), "rb")) {
        std::fclose(cur);
        const std::string bak = path + ".bak";
        std::remove(bak.c_str());
        if (std::rename(path.c_str(), bak.c_str()) != 0)
            throw std::runtime_error("Scp03KeyFile::write: cannot back up '" + path + "' to '" +
                                     bak + "'");
    }

    // 2) Write to a temp file, then atomically rename into place.
    const std::string tmp = path + ".tmp";
    FILE *fp = std::fopen(tmp.c_str(), "wb");
    if (!fp)
        throw std::runtime_error("Scp03KeyFile::write: cannot open '" + tmp + "' for writing");

    auto emit = [&](const char *tag, const uint8_t k[16]) {
        std::fprintf(fp, "%s ", tag);
        for (int i = 0; i < 16; ++i)
            std::fprintf(fp, "%02x", k[i]);
        std::fputc('\n', fp);
    };
    emit("ENC", keys.enc);
    emit("MAC", keys.mac);
    emit("DEK", keys.dek);

    if (std::fflush(fp) != 0 || std::fclose(fp) != 0) {
        std::remove(tmp.c_str());
        throw std::runtime_error("Scp03KeyFile::write: error flushing '" + tmp + "'");
    }
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        std::remove(tmp.c_str());
        throw std::runtime_error("Scp03KeyFile::write: cannot rename '" + tmp + "' to '" + path +
                                 "'");
    }
}

} // namespace Scp03KeyFile
} // namespace se05x
