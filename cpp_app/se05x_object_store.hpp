/**
 * @file se05x_object_store.hpp
 * @brief SE05x persistent object-store CRUD on top of the SSS key store.
 *
 * One responsibility: create / query / read / erase persisted objects in the
 * SE05x key store (RSA key handles, DER certificates, arbitrary binary blobs).
 * It does not perform cryptographic operations (see se05x_crypto.hpp) and it
 * does not implement higher-level provisioning flows (see se05x_provision.hpp).
 *
 * All failures are reported by throwing CryptoError.
 */

#pragma once
#include "se05x_crypto.hpp"

#include <cstdint>
#include <vector>

namespace se05x {

/**
 * @brief Erase a persisted object (key, certificate, or binary blob) from the SE.
 *
 * Canonical erase for every object type — the SSS API uses the same
 * @c sss_key_store_erase_key call regardless of cipher type.
 *
 * @param s   Active session.
 * @param id  SE object ID to erase.
 * @throws CryptoError if the object does not exist or the erase fails.
 */
void eraseObject(Session &s, uint32_t id);

/**
 * @brief Non-destructively check whether a SE object exists.
 *
 * Use this before genkey/write to implement idempotency: if the object already
 * exists and @c --force is not given, skip the write.
 *
 * @param s   Active session.
 * @param id  SE05x object ID to query.
 * @return    true if an object with @p id exists on the SE.
 */
bool objectExists(Session &s, uint32_t id);

/**
 * @brief Write a DER certificate (or arbitrary blob) as a binary SE object.
 *
 * If an object already exists at @p id it is erased first so the write is
 * idempotent.  The object is stored as @c kSSS_CipherType_Binary /
 * @c kKeyObject_Mode_Persistent.
 *
 * @param s    Active session.
 * @param id   SE05x object ID.
 * @param der  DER-encoded certificate bytes.
 * @throws CryptoError on SE failure.
 */
void writeCert(Session &s, uint32_t id, const std::vector<uint8_t> &der);

/**
 * @brief Write a plain binary blob to a persistent, rewritable SE object.
 * @param s      Active session.
 * @param id     SE05x object ID.
 * @param data   Bytes to store.
 * @param force  If the object already exists: erase+replace when true; otherwise
 *               leave it untouched.
 * @return       true if written, false if it already existed and @p force was false.
 * @throws CryptoError on SE failure.
 */
bool writeBinary(Session &s, uint32_t id, const std::vector<uint8_t> &data, bool force);

/**
 * @brief Read a binary SE object back.
 * @throws CryptoError if the object does not exist or cannot be read.
 */
std::vector<uint8_t> readBinary(Session &s, uint32_t id);

} // namespace se05x
