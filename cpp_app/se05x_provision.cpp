/**
 * @file se05x_provision.cpp
 * @brief SE05x provisioning helpers — UID, certificate storage, binding verification.
 */

#include "se05x_provision.hpp"

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
    // SE050_MAX_UID_LEN is 18 bytes per the NXP applet spec.
    constexpr size_t kUidLen = 18;
    std::vector<uint8_t> uid(kUidLen);
    size_t uidLen = uid.size();
    sss_status_t st = sss_session_prop_get_au8(
        s.session(), kSSS_SessionProp_UID, uid.data(), &uidLen);
    if (st != kStatus_SSS_Success)
        throw CryptoError(
            "readUid failed (0x6982 = SCP03 not established; "
            "set EX_SSS_BOOT_SCP03_PATH or verify SCP03 keys match the SE)", st);
    uid.resize(uidLen);
    return uid;
}

// Object existence check

bool objectExists(Session &s, uint32_t id) {
    sss_object_t obj{};
    if (sss_key_object_init(&obj, s.keystore()) != kStatus_SSS_Success)
        return false;
    sss_status_t st = sss_key_object_get_handle(&obj, id);
    sss_key_object_free(&obj);
    return (st == kStatus_SSS_Success);
}

// Binary certificate storage

void writeCert(Session &s, uint32_t id, const std::vector<uint8_t> &der) {
    // Erase any prior occupant so the write is idempotent.
    if (objectExists(s, id)) {
        sss_object_t old{};
        sss_key_object_init(&old, s.keystore());
        sss_key_object_get_handle(&old, id);
        sss_key_store_erase_key(s.keystore(), &old);
        sss_key_object_free(&old);
    }

    sss_object_t obj{};
    check(sss_key_object_init(&obj, s.keystore()),
          "sss_key_object_init");
    check(sss_key_object_allocate_handle(
              &obj, id,
              kSSS_KeyPart_Default,
              kSSS_CipherType_Binary,
              der.size(),
              kKeyObject_Mode_Persistent),
          "sss_key_object_allocate_handle(cert)");
    check(sss_key_store_set_key(
              s.keystore(), &obj,
              der.data(), der.size(),
              der.size() * 8,
              nullptr, 0),
          "sss_key_store_set_key(cert)");
    sss_key_object_free(&obj);
}

// Binding verification

bool verifyBindingRsa(Session &s, uint32_t keyId,
                      const std::vector<uint8_t> &certDer) {
    // 1. Hardware nonce → digest to sign.
    auto nonce  = getRandom(s, 32);
    auto digest = sha256v(nonce);

    // 2. Sign with the SE private key (RSASSA-PKCS1-v1_5 / SHA-256).
    auto sig = RsaKey::open(s, keyId).sign(digest);

    // 3. Parse the certificate with mbedTLS and verify the signature.
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    int r = mbedtls_x509_crt_parse_der(&crt, certDer.data(), certDer.size());
    if (r != 0) {
        mbedtls_x509_crt_free(&crt);
        throw std::runtime_error("verifyBindingRsa: cannot parse certificate");
    }
    r = mbedtls_pk_verify(&crt.pk, MBEDTLS_MD_SHA256,
                          digest.data(), digest.size(),
                          sig.data(), sig.size());
    mbedtls_x509_crt_free(&crt);
    return (r == 0);
}

} // namespace se05x
