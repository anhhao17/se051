#pragma once

#include <cstdarg>
#include <cstdio>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

/**
 * @brief Output sink for the SE05x CLI.
 *
 * - Default (no --log): result output goes to stdout; status lines go to stderr.
 * - With --log <path>:  result output goes to the file; status lines go to
 *   both stderr (live feedback on terminal) and the file (permanent record).
 *
 * Binary data is never written through Log — use writeFile() + --out for that.
 */
class Log {
public:
    /** @param path  Log file path, or nullptr to write to stdout. */
    explicit Log(const char *path = nullptr)
        : f_(path ? std::fopen(path, "a") : stdout), own_(path != nullptr) {
        if (own_ && !f_)
            throw std::runtime_error(std::string("cannot open log file: ") + path);
    }

    ~Log() { if (own_ && f_) std::fclose(f_); }

    Log(const Log &)            = delete;
    Log &operator=(const Log &) = delete;

    /** Result output: hex strings, PEM, "VERIFY OK", UID text, etc. */
    void print(const char *fmt, ...) {
        va_list ap; va_start(ap, fmt);
        std::vfprintf(f_, fmt, ap); va_end(ap);
        std::fflush(f_);
    }

    /**
     * Status lines ([i] / [+] / [!]).
     * Always written to stderr; also written to the log file when one is open.
     */
    void status(const char *fmt, ...) {
        va_list a, b; va_start(a, fmt); va_copy(b, a);
        std::vfprintf(stderr, fmt, a); va_end(a);
        if (own_) { std::vfprintf(f_, fmt, b); std::fflush(f_); }
        va_end(b);
    }

    /** Print bytes as lowercase hex followed by a newline. */
    void hex(const std::vector<uint8_t> &v) {
        for (uint8_t b : v) std::fprintf(f_, "%02x", b);
        std::fputc('\n', f_); std::fflush(f_);
    }

private:
    FILE *f_;
    bool  own_;
};
