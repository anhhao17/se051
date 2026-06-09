/**
 * @file se05x_provision.cpp
 * @brief SE05x provisioning helpers - UID, certificate storage, binding verification.
 */

#include "se05x_provision.hpp"
#include "log.hpp"

#include <cstring>
#include <stdexcept>
#include <vector>

extern "C" {
#include <fsl_sss_api.h>
#include <fsl_sss_se05x_apis.h>
#include "mbedtls/sha256.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
}

namespace se05x {

namespace {

std::vector<uint8_t> sha256v(const std::vector<uint8_t> &in) {
    std::vector<uint8_t> out(32);
    mbedtls_sha256_ret(in.data(), in.size(), out.data(), 0);
    return out;
}

} // namespace

// UID

std::vector<uint8_t> readUid(Session &s) {
    LOG_DEBUG("readUid: requesting 18-byte chip UID\n");
    constexpr size_t     kUidLen = 18;
    std::vector<uint8_t> uid(kUidLen);
    size_t               uidLen = uid.size();
    sss_status_t         st =
        sss_session_prop_get_au8(s.session(), kSSS_SessionProp_UID, uid.data(), &uidLen);
    if (st != kStatus_SSS_Success)
        throw CryptoError("readUid failed (0x6982 = SCP03 not established; "
                          "set EX_SSS_BOOT_SCP03_PATH or verify SCP03 keys match the SE)",
                          st);
    uid.resize(uidLen);
    return uid;
}

// Object existence check

bool objectExists(Session &s, uint32_t id) {
    sss_object_t obj{};
    if (sss_key_object_init(&obj, s.keystore()) != kStatus_SSS_Success) return false;
    sss_status_t st = sss_key_object_get_handle(&obj, id);
    sss_key_object_free(&obj);
    return (st == kStatus_SSS_Success);
}

// Binary certificate storage

void writeCert(Session &s, uint32_t id, const std::vector<uint8_t> &der) {
    LOG_DEBUG("writeCert: id=0x%08X, %zu bytes\n", id, der.size());
    if (objectExists(s, id)) {
        LOG_DEBUG("writeCert: erasing existing object 0x%08X\n", id);
        sss_object_t old{};
        sss_key_object_init(&old, s.keystore());
        sss_key_object_get_handle(&old, id);
        sss_key_store_erase_key(s.keystore(), &old);
        sss_key_object_free(&old);
    }

    sss_object_t obj{};
    check(sss_key_object_init(&obj, s.keystore()), "sss_key_object_init");
    check(sss_key_object_allocate_handle(&obj, id, kSSS_KeyPart_Default,
                                         kSSS_CipherType_Binary, der.size(),
                                         kKeyObject_Mode_Persistent),
          "sss_key_object_allocate_handle(cert)");
    check(sss_key_store_set_key(s.keystore(), &obj, der.data(), der.size(),
                                der.size() * 8, nullptr, 0),
          "sss_key_store_set_key(cert)");
    sss_key_object_free(&obj);
}

// Binding verification

bool verifyBindingRsa(Session &s, uint32_t keyId, const std::vector<uint8_t> &certDer) {
    LOG_DEBUG("verifyBinding: key=0x%08X, cert=%zu bytes\n", keyId, certDer.size());

    LOG_DEBUG("verifyBinding: generating 32-byte TRNG nonce\n");
    auto nonce  = getRandom(s, 32);
    auto digest = sha256v(nonce);

    LOG_DEBUG("verifyBinding: signing digest with SE key 0x%08X\n", keyId);
    auto sig = RsaKey::open(s, keyId).sign(digest);

    LOG_DEBUG("verifyBinding: verifying signature against cert pubkey\n");
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    int r = mbedtls_x509_crt_parse_der(&crt, certDer.data(), certDer.size());
    if (r != 0) {
        mbedtls_x509_crt_free(&crt);
        throw std::runtime_error("verifyBindingRsa: cannot parse certificate");
    }
    r = mbedtls_pk_verify(&crt.pk, MBEDTLS_MD_SHA256, digest.data(), digest.size(),
                          sig.data(), sig.size());
    mbedtls_x509_crt_free(&crt);
    LOG_DEBUG("verifyBinding: mbedTLS result %d (%s)\n", r, r == 0 ? "OK" : "FAIL");
    return (r == 0);
}

} // namespace se05x
