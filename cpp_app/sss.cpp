/**
 * @file sss.cpp
 * @brief SSS layer implementation: primitives, RsaKey, and SssBackend.
 */

#include "sss.hpp"
#include "log.hpp"

#include <cstdio>
#include <stdexcept>
#include <utility>

extern "C" {
#include <fsl_sss_se05x_apis.h>
#include <fsl_sss_se05x_policy.h>
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509_crt.h"
}

namespace se05x {

// --- Status helpers ---

std::string CryptoError::hex(sss_status_t st) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%04x", static_cast<unsigned>(st));
    return buf;
}

void check(sss_status_t st, const char *where) {
    if (st != kStatus_SSS_Success)
        throw CryptoError(std::string("SSS call failed: ") + where, st);
}

std::vector<uint8_t> sha256(const std::vector<uint8_t> &in) {
    std::vector<uint8_t> out(32);
    mbedtls_sha256_ret(in.data(), in.size(), out.data(), 0);
    return out;
}

// --- SssConnection (owns the boot context lifecycle) ---

SssConnection::SssConnection(const char *port, bool selectApplet) : session_(&ctx_) {
    // Rotation targets the ISD (card manager); everything else selects the applet.
    if (!selectApplet)
        ctx_.se05x_open_ctx.skip_select_applet = 1;

    check(ex_sss_boot_open(&ctx_, port), "ex_sss_boot_open (set --port or $EX_SSS_BOOT_SSS_PORT)");
    opened_ = true;
    check(ex_sss_key_store_and_object_init(&ctx_), "ex_sss_key_store_and_object_init");
}

SssConnection::~SssConnection() {
    if (opened_)
        ex_sss_session_close(&ctx_);
}

// --- RsaKey ---

RsaKey RsaKey::generate(Session &s, uint32_t keyId, RsaBits bits, sss_policy_t *policy) {
    RsaKey k(s);
    k.bits_ = static_cast<size_t>(bits);
    k.owns_ = true;

    k.obj_.allocate(keyId, kSSS_KeyPart_Pair, kSSS_CipherType_RSA, k.bits_ / 8,
                    "key_object_allocate_handle(RSA)");
    check(sss_key_store_generate_key(s.keystore(), k.obj_.raw(), static_cast<uint32_t>(k.bits_),
                                     policy),
          "key_store_generate_key(RSA)");
    return k;
}

RsaKey RsaKey::open(Session &s, uint32_t keyId) {
    RsaKey k(s);
    k.owns_ = false;
    k.obj_.open(keyId, "key_object_get_handle");
    return k;
}

std::vector<uint8_t> RsaKey::sign(const std::vector<uint8_t> &digest) {
    sss_asymmetric_t ctx{};
    check(sss_asymmetric_context_init(&ctx, s_.session(), obj_.raw(),
                                      kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256, kMode_SSS_Sign),
          "asymmetric_context_init(RSA sign)");
    std::vector<uint8_t> sig(bits_ / 8);
    size_t sigLen = sig.size();
    sss_status_t st = sss_asymmetric_sign_digest(&ctx, const_cast<uint8_t *>(digest.data()),
                                                 digest.size(), sig.data(), &sigLen);
    sss_asymmetric_context_free(&ctx);
    check(st, "asymmetric_sign_digest(RSA)");
    sig.resize(sigLen);
    return sig;
}

bool RsaKey::verify(const std::vector<uint8_t> &digest, const std::vector<uint8_t> &signature) {
    sss_asymmetric_t ctx{};
    check(sss_asymmetric_context_init(&ctx, s_.session(), obj_.raw(),
                                      kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256, kMode_SSS_Verify),
          "asymmetric_context_init(RSA verify)");
    sss_status_t st =
        sss_asymmetric_verify_digest(&ctx, const_cast<uint8_t *>(digest.data()), digest.size(),
                                     const_cast<uint8_t *>(signature.data()), signature.size());
    sss_asymmetric_context_free(&ctx);
    return st == kStatus_SSS_Success;
}

std::vector<uint8_t> RsaKey::encrypt(const std::vector<uint8_t> &plaintext) {
    sss_asymmetric_t ctx{};
    check(sss_asymmetric_context_init(&ctx, s_.session(), obj_.raw(),
                                      kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA256, kMode_SSS_Encrypt),
          "asymmetric_context_init(RSA enc)");
    std::vector<uint8_t> out(bits_ / 8);
    size_t outLen = out.size();
    sss_status_t st = sss_asymmetric_encrypt(&ctx, const_cast<uint8_t *>(plaintext.data()),
                                             plaintext.size(), out.data(), &outLen);
    sss_asymmetric_context_free(&ctx);
    check(st, "asymmetric_encrypt(RSA)");
    out.resize(outLen);
    return out;
}

std::vector<uint8_t> RsaKey::decrypt(const std::vector<uint8_t> &ciphertext) {
    sss_asymmetric_t ctx{};
    check(sss_asymmetric_context_init(&ctx, s_.session(), obj_.raw(),
                                      kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA256, kMode_SSS_Decrypt),
          "asymmetric_context_init(RSA dec)");
    std::vector<uint8_t> out(bits_ / 8);
    size_t outLen = out.size();
    sss_status_t st = sss_asymmetric_decrypt(&ctx, const_cast<uint8_t *>(ciphertext.data()),
                                             ciphertext.size(), out.data(), &outLen);
    sss_asymmetric_context_free(&ctx);
    check(st, "asymmetric_decrypt(RSA)");
    out.resize(outLen);
    return out;
}

std::vector<uint8_t> RsaKey::publicKeyDer() {
    std::vector<uint8_t> buf(bits_ / 8 + 64);
    size_t len = buf.size();
    size_t bits = 0;
    check(sss_key_store_get_key(s_.keystore(), obj_.raw(), buf.data(), &len, &bits),
          "key_store_get_key(RSA pub)");
    buf.resize(len);
    return buf;
}

RsaKey::RsaKey(RsaKey &&o) noexcept
    : s_(o.s_), obj_(std::move(o.obj_)), bits_(o.bits_), owns_(o.owns_) {
    o.owns_ = false;
}

RsaKey::~RsaKey() {}

// --- Policy-aware key generation (SSS-only) ---

namespace {

RsaKey generateRsaWithPolicy(Session &s, uint32_t keyId, RsaBits bits, KeyPolicy policy) {
    if (policy == KeyPolicy::Full)
        return RsaKey::generate(s, keyId, bits, nullptr);

    // SE05x 07.02 policy notes (see fsl_sss_se05x_policy.c):
    //   - Asym key policy handles: can_Sign, can_Decrypt, can_Gen, can_Import_Export
    //   - Common policy handles:   can_Read, can_Write, can_Delete, req_Sm
    sss_policy_u asymPol{};
    asymPol.type = KPolicy_Asym_Key;
    asymPol.auth_obj_id = 0;
    asymPol.policy.asymmkey.can_Sign = 1;
    asymPol.policy.asymmkey.can_Decrypt = (policy == KeyPolicy::SignDecrypt) ? 1 : 0;
    asymPol.policy.asymmkey.can_Gen = 1; // needed for on-chip generation
    // can_Import_Export = 0  ->  private key cannot be exported

    sss_policy_u commonPol{};
    commonPol.type = KPolicy_Common;
    commonPol.auth_obj_id = 0;
    commonPol.policy.common.can_Read = 1;   // allow public key read (CSR / rsa pub)
    commonPol.policy.common.can_Write = 0;  // prevent overwriting key material
    commonPol.policy.common.can_Delete = 0; // non-deletable once provisioned
    commonPol.policy.common.req_Sm = 1;     // all operations require SCP03

    sss_policy_t pol{};
    pol.policies[0] = &asymPol;
    pol.policies[1] = &commonPol;
    pol.nPolicies = 2;

    LOG_DEBUG("generateKey: id=0x%08X policy=%s\n", keyId,
              policy == KeyPolicy::SignOnly ? "sign-only" : "sign-decrypt");
    return RsaKey::generate(s, keyId, bits, &pol);
}

} // namespace

} // namespace se05x

// --- SssBackend: crypto (ICryptoBackend) ---

std::vector<uint8_t> SssBackend::getRandom(size_t n) {
    sss_rng_context_t rng{};
    se05x::check(sss_rng_context_init(&rng, s_.session()), "rng_context_init");
    std::vector<uint8_t> out(n);
    sss_status_t st = sss_rng_get_random(&rng, out.data(), out.size());
    sss_rng_context_free(&rng);
    se05x::check(st, "rng_get_random");
    return out;
}

bool SssBackend::keyExists(uint32_t id) {
    return objectExists(id);
}

void SssBackend::deleteKey(uint32_t id) {
    if (objectExists(id))
        eraseObject(id);
}

void SssBackend::generateKey(uint32_t id, se05x::RsaBits bits, se05x::KeyPolicy policy) {
    LOG_DEBUG("sss: generate id=0x%08X bits=%zu\n", id, static_cast<size_t>(bits));
    se05x::generateRsaWithPolicy(s_, id, bits, policy);
}

std::vector<uint8_t> SssBackend::getSpki(uint32_t id) {
    return se05x::RsaKey::open(s_, id).publicKeyDer();
}

std::vector<uint8_t> SssBackend::sign(uint32_t id, const std::vector<uint8_t> &msg) {
    return se05x::RsaKey::open(s_, id).sign(se05x::sha256(msg));
}

bool SssBackend::verify(uint32_t id, const std::vector<uint8_t> &msg,
                        const std::vector<uint8_t> &sig) {
    return se05x::RsaKey::open(s_, id).verify(se05x::sha256(msg), sig);
}

std::string SssBackend::makeCsr(uint32_t id, const std::string &subjectDn) {
    return se05x::RsaKey::open(s_, id).makeCsr(subjectDn);
}

// --- SssBackend: object-store helpers ---

bool SssBackend::objectExists(uint32_t id) {
    se05x::KeyObject obj(s_);
    return obj.bind(id);
}

void SssBackend::eraseObject(uint32_t id) {
    se05x::KeyObject obj(s_);
    obj.open(id, "key_object_get_handle(erase)");
    se05x::check(sss_key_store_erase_key(s_.keystore(), obj.raw()), "key_store_erase_key");
}

void SssBackend::storeBinary(uint32_t id, const std::vector<uint8_t> &data, const char *tag) {
    se05x::KeyObject obj(s_);
    obj.allocate(id, kSSS_KeyPart_Default, kSSS_CipherType_Binary, data.size(), tag);
    se05x::check(sss_key_store_set_key(s_.keystore(), obj.raw(), data.data(), data.size(),
                                       data.size() * 8, nullptr, 0),
                 tag);
}

// --- SssBackend: management ---

std::vector<uint8_t> SssBackend::uid() {
    LOG_DEBUG("uid: requesting 18-byte chip UID\n");
    constexpr size_t kUidLen = 18;
    std::vector<uint8_t> uid(kUidLen);
    size_t uidLen = uid.size();
    sss_status_t st =
        sss_session_prop_get_au8(s_.session(), kSSS_SessionProp_UID, uid.data(), &uidLen);
    if (st != kStatus_SSS_Success)
        throw se05x::CryptoError("uid failed (0x6982 = SCP03 not established; "
                                 "set EX_SSS_BOOT_SCP03_PATH or verify SCP03 keys match the SE)",
                                 st);
    uid.resize(uidLen);
    return uid;
}

void SssBackend::writeCert(uint32_t id, const std::vector<uint8_t> &der) {
    LOG_DEBUG("writeCert: id=0x%08X, %zu bytes\n", id, der.size());
    if (objectExists(id)) {
        LOG_DEBUG("writeCert: erasing existing object 0x%08X\n", id);
        eraseObject(id);
    }
    storeBinary(id, der, "sss_key_object_allocate_handle(cert)");
}

bool SssBackend::writeBinary(uint32_t id, const std::vector<uint8_t> &data, bool force) {
    LOG_DEBUG("writeBinary: id=0x%08X, %zu bytes, force=%d\n", id, data.size(), force);
    if (objectExists(id)) {
        if (!force) {
            LOG_INFO("writeBinary: object 0x%08X already exists (use --force to overwrite)\n", id);
            return false;
        }
        LOG_DEBUG("writeBinary: erasing existing object 0x%08X\n", id);
        eraseObject(id);
    }
    storeBinary(id, data, "sss_key_object_allocate_handle(bin)");
    return true;
}

std::vector<uint8_t> SssBackend::readBinary(uint32_t id) {
    LOG_DEBUG("readBinary: id=0x%08X\n", id);
    se05x::KeyObject obj(s_);
    if (!obj.bind(id))
        throw se05x::CryptoError("readBinary: object not found", kStatus_SSS_Fail);
    std::vector<uint8_t> buf(2048);
    size_t len = buf.size();
    size_t bitLen = buf.size() * 8;
    se05x::check(sss_key_store_get_key(s_.keystore(), obj.raw(), buf.data(), &len, &bitLen),
                 "sss_key_store_get_key(bin)");
    buf.resize(len);
    return buf;
}

bool SssBackend::verifyBinding(uint32_t id, const std::vector<uint8_t> &certDer) {
    LOG_DEBUG("verifyBinding: key=0x%08X, cert=%zu bytes\n", id, certDer.size());

    auto nonce = getRandom(32);
    auto digest = se05x::sha256(nonce);

    LOG_DEBUG("verifyBinding: signing digest with SE key 0x%08X\n", id);
    auto sig = se05x::RsaKey::open(s_, id).sign(digest);

    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    int r = mbedtls_x509_crt_parse_der(&crt, certDer.data(), certDer.size());
    if (r != 0) {
        mbedtls_x509_crt_free(&crt);
        throw std::runtime_error("verifyBinding: cannot parse certificate");
    }
    r = mbedtls_pk_verify(&crt.pk, MBEDTLS_MD_SHA256, digest.data(), digest.size(), sig.data(),
                          sig.size());
    mbedtls_x509_crt_free(&crt);
    LOG_DEBUG("verifyBinding: mbedTLS result %d (%s)\n", r, r == 0 ? "OK" : "FAIL");
    return (r == 0);
}
