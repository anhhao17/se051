/**
 * @file output.hpp
 * @brief Result and file output for CLI commands (single responsibility).
 *
 * Centralises everything commands do with their output: write bytes to --out or
 * print them as hex, render SPKI as DER or PEM, emit text, print a result line.
 * Commands never touch the Log result stream or do file I/O directly.
 */

#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct Args;

/** @brief Renders command results to files or the result stream. */
class OutputWriter {
public:
    /** @brief Bytes -> --out file (logs "wrote N bytes"), else hex to result stream. */
    void bytes(const Args &a, const std::vector<uint8_t> &d) const;

    /** @brief SPKI DER -> PEM if --pem, else handled as bytes(). */
    void spki(const Args &a, const std::vector<uint8_t> &spki) const;

    /** @brief Text -> --out file, else to the result stream. */
    void text(const Args &a, const std::string &text) const;

    /** @brief A single result line (e.g. "VERIFY OK"); printf-style. */
    void line(const char *fmt, ...) const;

    static std::vector<uint8_t> readFile(const std::string &path);
    static void writeFile(const std::string &path, const std::vector<uint8_t> &d);
};
