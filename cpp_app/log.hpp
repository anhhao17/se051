#pragma once

#include <cstdarg>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <stdexcept>
#include <string>
#include <vector>

/**
 * @brief Global output sink for the SE05x CLI.
 *
 * Initialise once at program start with Log::init().  All source files then
 * reach it via the LOG_* macros, which capture __FILE__ and __LINE__ so every
 * diagnostic line is self-identifying.
 *
 * Two output streams:
 *   Status/diagnostic (LOG_*): timestamped lines with source location.
 *     Always go to stderr; also written to the log file when --log is active.
 *   Result data (Log::get().print() / .hex()): raw output — hex, PEM,
 *     "VERIFY OK", UID.  Goes to the log file, or stdout if no --log.
 *     No timestamp or location prefix so the output stays machine-readable.
 *
 * Log levels:
 *   DEBUG  [d]  verbose trace; filtered by default (min = INFO)
 *   INFO   [i]  normal progress messages
 *   OK     [+]  success confirmations
 *   ERROR  [!]  failures
 */
class Log {
public:
    enum Level { DEBUG = 0, INFO = 1, OK = 2, ERROR = 3 };

    /**
     * Initialise the global logger.  Call once in main() before any LOG_* use.
     * Uses a static-local instance so subsequent calls are ignored.
     * Throws std::runtime_error if @p path cannot be opened for writing.
     */
    static void init(const char *path = nullptr, Level min = INFO) {
        static Log inst(path, min);
        s_instance_ = &inst;
    }

    /**
     * Return the global logger.  Falls back to a stdout/INFO logger if init()
     * was never called (e.g. in unit tests).
     */
    static Log &get() {
        if (s_instance_) return *s_instance_;
        static Log fallback;
        return fallback;
    }

    /**
     * Write a timestamped status line with source location.
     * Filtered by the minimum level.  Goes to stderr and (if --log) also to
     * the log file.  Use the LOG_* macros instead of calling directly.
     */
    void logAt(Level lvl, const char *file, int line, const char *fmt, ...) {
        if (lvl < min_) return;
        va_list a, b;
        va_start(a, fmt);
        va_copy(b, a);
        writeLine(stderr, lvl, file, line, fmt, a);
        va_end(a);
        if (own_) { writeLine(f_, lvl, file, line, fmt, b); }
        va_end(b);
    }

    /** Result data output — no timestamp or location prefix. */
    void print(const char *fmt, ...) {
        va_list ap; va_start(ap, fmt);
        std::vfprintf(f_, fmt, ap); va_end(ap);
        std::fflush(f_);
    }

    /** Print bytes as lowercase hex followed by a newline. */
    void hex(const std::vector<uint8_t> &v) {
        for (uint8_t b : v) std::fprintf(f_, "%02x", b);
        std::fputc('\n', f_); std::fflush(f_);
    }

private:
    explicit Log(const char *path = nullptr, Level min = INFO)
        : f_(path ? std::fopen(path, "a") : stdout), own_(path != nullptr), min_(min) {
        if (own_ && !f_)
            throw std::runtime_error(std::string("cannot open log file: ") + path);
    }
    ~Log() { if (own_ && f_) std::fclose(f_); }
    Log(const Log &)            = delete;
    Log &operator=(const Log &) = delete;

    static const char *tag(Level l) {
        switch (l) {
            case DEBUG: return "[d]";
            case INFO:  return "[i]";
            case OK:    return "[+]";
            case ERROR: return "[!]";
        }
        return "[?]";
    }

    static const char *shortname(const char *path) {
        const char *s = std::strrchr(path, '/');
        return s ? s + 1 : path;
    }

    void writeLine(FILE *dst, Level lvl, const char *file, int line,
                   const char *fmt, va_list ap) {
        char ts[20];
        std::time_t t = std::time(nullptr);
        std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
        std::fprintf(dst, "%s %s %s:%d: ", ts, tag(lvl), shortname(file), line);
        std::vfprintf(dst, fmt, ap);
        std::fflush(dst);
    }

    FILE  *f_;
    bool   own_;
    Level  min_;

    inline static Log *s_instance_ = nullptr;
};

#define LOG_DEBUG(...) Log::get().logAt(Log::DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_INFO(...)  Log::get().logAt(Log::INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_OK(...)    Log::get().logAt(Log::OK,    __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERROR(...) Log::get().logAt(Log::ERROR, __FILE__, __LINE__, __VA_ARGS__)
