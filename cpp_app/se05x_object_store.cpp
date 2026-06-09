/**
 * @file se05x_object_store.cpp
 * @brief SE05x persistent object-store CRUD - erase, existence, binary read/write.
 */

#include "se05x_object_store.hpp"
#include "log.hpp"

extern "C" {
#include <fsl_sss_api.h>
}

namespace se05x {

namespace {

void storeBinaryObject(Session &s, uint32_t id, const std::vector<uint8_t> &data, const char *tag) {
    sss_object_t obj{};
    check(sss_key_object_init(&obj, s.keystore()), "sss_key_object_init");
    check(sss_key_object_allocate_handle(&obj, id, kSSS_KeyPart_Default, kSSS_CipherType_Binary,
                                         data.size(), kKeyObject_Mode_Persistent),
          tag);
    check(sss_key_store_set_key(s.keystore(), &obj, data.data(), data.size(), data.size() * 8,
                                nullptr, 0),
          tag);
    sss_key_object_free(&obj);
}

} // namespace

void eraseObject(Session &s, uint32_t id) {
    sss_object_t obj{};
    check(sss_key_object_init(&obj, s.keystore()), "key_object_init(erase)");
    check(sss_key_object_get_handle(&obj, id), "key_object_get_handle(erase)");
    sss_status_t st = sss_key_store_erase_key(s.keystore(), &obj);
    sss_key_object_free(&obj);
    check(st, "key_store_erase_key");
}

bool objectExists(Session &s, uint32_t id) {
    sss_object_t obj{};
    if (sss_key_object_init(&obj, s.keystore()) != kStatus_SSS_Success)
        return false;
    sss_status_t st = sss_key_object_get_handle(&obj, id);
    sss_key_object_free(&obj);
    return (st == kStatus_SSS_Success);
}

// Binary certificate storage (always overwrites; idempotent erase-then-write).
void writeCert(Session &s, uint32_t id, const std::vector<uint8_t> &der) {
    LOG_DEBUG("writeCert: id=0x%08X, %zu bytes\n", id, der.size());
    if (objectExists(s, id)) {
        LOG_DEBUG("writeCert: erasing existing object 0x%08X\n", id);
        eraseObject(s, id);
    }
    storeBinaryObject(s, id, der, "sss_key_object_allocate_handle(cert)");
}

// Plain binary object storage; returns false (no-op) if the object exists and force is false.
bool writeBinary(Session &s, uint32_t id, const std::vector<uint8_t> &data, bool force) {
    LOG_DEBUG("writeBinary: id=0x%08X, %zu bytes, force=%d\n", id, data.size(), force);
    if (objectExists(s, id)) {
        if (!force) {
            LOG_INFO("writeBinary: object 0x%08X already exists (use --force to overwrite)\n", id);
            return false;
        }
        LOG_DEBUG("writeBinary: erasing existing object 0x%08X\n", id);
        eraseObject(s, id);
    }
    storeBinaryObject(s, id, data, "sss_key_object_allocate_handle(bin)");
    return true;
}

std::vector<uint8_t> readBinary(Session &s, uint32_t id) {
    LOG_DEBUG("readBinary: id=0x%08X\n", id);
    sss_object_t obj{};
    check(sss_key_object_init(&obj, s.keystore()), "sss_key_object_init(bin read)");
    if (sss_key_object_get_handle(&obj, id) != kStatus_SSS_Success) {
        sss_key_object_free(&obj);
        throw CryptoError("readBinary: object not found", kStatus_SSS_Fail);
    }
    std::vector<uint8_t> buf(2048);
    size_t len = buf.size();
    size_t bitLen = buf.size() * 8;
    sss_status_t st = sss_key_store_get_key(s.keystore(), &obj, buf.data(), &len, &bitLen);
    sss_key_object_free(&obj);
    check(st, "sss_key_store_get_key(bin)");
    buf.resize(len);
    return buf;
}

} // namespace se05x
