/**
 * @file scp03_keyfile.hpp
 * @brief Read/write the SCP03 static-key file (ENC/MAC/DEK hex lines).
 *
 * Single responsibility: own the on-disk format of the SCP03 key file used by
 * the plug-and-trust boot path ($EX_SSS_BOOT_SCP03_PATH) and by the NXP demo.
 * Both the rotation flow (needs the current DEK) and the CLI (persists new keys
 * after a successful rotation) go through here, so the format lives in exactly
 * one place.
 *
 * File format (one key per line, case-insensitive tag, lowercase hex):
 *     ENC <32 hex>
 *     MAC <32 hex>
 *     DEK <32 hex>
 */

#pragma once
#include "scp03_rotate.hpp" // se05x::Scp03KeySet
#include <string>

namespace se05x {

/** @brief Persistence for the SCP03 static-key file. */
namespace Scp03KeyFile {

/**
 * @brief Read ENC/MAC/DEK from @p path.
 * @throws std::runtime_error if the file is missing or any key line is absent
 *         or malformed (not exactly 32 hex chars).
 */
Scp03KeySet read(const std::string &path);

/**
 * @brief Read only the DEK from @p path (the rotation flow needs just this).
 * @returns true and fills @p dek (16 bytes) on success; false if the file or a
 *          valid "DEK <32 hex>" line is absent.
 */
bool readDek(const std::string &path, uint8_t dek[16]);

/**
 * @brief Atomically write @p keys to @p path.
 *
 * Backs up any existing file to "<path>.bak" first, writes to a temporary file,
 * then renames it over @p path so a crash never leaves a half-written key file.
 *
 * @throws std::runtime_error on any I/O failure.  On failure the original file
 *         (and its .bak) are left intact.
 */
void write(const std::string &path, const Scp03KeySet &keys);

} // namespace Scp03KeyFile

} // namespace se05x
