// se05x_crypto.cpp
#include "se05x_crypto.hpp"

#include <cstdio>

namespace se05x {

std::string CryptoError::hex(sss_status_t st) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%04x", static_cast<unsigned>(st));
    return buf;
}

void check(sss_status_t st, const char *where) {
    if (st != kStatus_SSS_Success)
        throw CryptoError(std::string("SSS call failed: ") + where, st);
}

void eraseKey(Session &s, uint32_t keyId) {
    sss_object_t obj{};
    check(sss_key_object_init(&obj, s.keystore()), "key_object_init(erase)");
    check(sss_key_object_get_handle(&obj, keyId), "key_object_get_handle(erase)");
    check(sss_key_store_erase_key(s.keystore(), &obj), "key_store_erase_key");
}

namespace {
void openHandle(Session &s, sss_object_t *obj, uint32_t keyId) {
    check(sss_key_object_init(obj, s.keystore()), "key_object_init");
    check(sss_key_object_get_handle(obj, keyId), "key_object_get_handle");
}
} // namespace

std::vector<uint8_t> getRandom(Session &s, size_t numBytes) {
    sss_rng_context_t rng{};
    check(sss_rng_context_init(&rng, s.session()), "rng_context_init");
    std::vector<uint8_t> out(numBytes);
    sss_status_t         st = sss_rng_get_random(&rng, out.data(), out.size());
    sss_rng_context_free(&rng);
    check(st, "rng_get_random");
    return out;
}

RsaKey RsaKey::generate(Session &s, uint32_t keyId, RsaBits bits) {
    RsaKey k(s);
    k.bits_ = static_cast<size_t>(bits);
    k.owns_ = true;

    check(sss_key_object_init(&k.obj_, s.keystore()), "key_object_init");
    check(sss_key_object_allocate_handle(&k.obj_, keyId, kSSS_KeyPart_Pair,
                                         kSSS_CipherType_RSA, k.bits_ / 8,
                                         kKeyObject_Mode_Persistent),
          "key_object_allocate_handle(RSA)");
    check(sss_key_store_generate_key(s.keystore(), &k.obj_,
                                     static_cast<uint32_t>(k.bits_), nullptr),
          "key_store_generate_key(RSA)");
    return k;
}

RsaKey RsaKey::open(Session &s, uint32_t keyId) {
    RsaKey k(s);
    k.owns_ = false;
    openHandle(s, &k.obj_, keyId);
    return k;
}

std::vector<uint8_t> RsaKey::sign(const std::vector<uint8_t> &digest) {
    sss_asymmetric_t ctx{};
    check(sss_asymmetric_context_init(&ctx, s_.session(), &obj_,
                                      kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256,
                                      kMode_SSS_Sign),
          "asymmetric_context_init(RSA sign)");
    std::vector<uint8_t> sig(bits_ / 8);
    size_t               sigLen = sig.size();
    sss_status_t         st     = sss_asymmetric_sign_digest(
        &ctx, const_cast<uint8_t *>(digest.data()), digest.size(), sig.data(), &sigLen);
    sss_asymmetric_context_free(&ctx);
    check(st, "asymmetric_sign_digest(RSA)");
    sig.resize(sigLen);
    return sig;
}

bool RsaKey::verify(const std::vector<uint8_t> &digest,
                    const std::vector<uint8_t> &signature) {
    sss_asymmetric_t ctx{};
    check(sss_asymmetric_context_init(&ctx, s_.session(), &obj_,
                                      kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256,
                                      kMode_SSS_Verify),
          "asymmetric_context_init(RSA verify)");
    sss_status_t st = sss_asymmetric_verify_digest(
        &ctx, const_cast<uint8_t *>(digest.data()), digest.size(),
        const_cast<uint8_t *>(signature.data()), signature.size());
    sss_asymmetric_context_free(&ctx);
    return st == kStatus_SSS_Success;
}

std::vector<uint8_t> RsaKey::encrypt(const std::vector<uint8_t> &plaintext) {
    sss_asymmetric_t ctx{};
    check(sss_asymmetric_context_init(&ctx, s_.session(), &obj_,
                                      kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA256,
                                      kMode_SSS_Encrypt),
          "asymmetric_context_init(RSA enc)");
    std::vector<uint8_t> out(bits_ / 8);
    size_t               outLen = out.size();
    sss_status_t         st =
        sss_asymmetric_encrypt(&ctx, const_cast<uint8_t *>(plaintext.data()),
                               plaintext.size(), out.data(), &outLen);
    sss_asymmetric_context_free(&ctx);
    check(st, "asymmetric_encrypt(RSA)");
    out.resize(outLen);
    return out;
}

std::vector<uint8_t> RsaKey::decrypt(const std::vector<uint8_t> &ciphertext) {
    sss_asymmetric_t ctx{};
    check(sss_asymmetric_context_init(&ctx, s_.session(), &obj_,
                                      kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA256,
                                      kMode_SSS_Decrypt),
          "asymmetric_context_init(RSA dec)");
    std::vector<uint8_t> out(bits_ / 8);
    size_t               outLen = out.size();
    sss_status_t         st =
        sss_asymmetric_decrypt(&ctx, const_cast<uint8_t *>(ciphertext.data()),
                               ciphertext.size(), out.data(), &outLen);
    sss_asymmetric_context_free(&ctx);
    check(st, "asymmetric_decrypt(RSA)");
    out.resize(outLen);
    return out;
}

std::vector<uint8_t> RsaKey::publicKeyDer() {
    std::vector<uint8_t> buf(bits_ / 8 + 64);
    size_t               len  = buf.size();
    size_t               bits = 0;
    check(sss_key_store_get_key(s_.keystore(), &obj_, buf.data(), &len, &bits),
          "key_store_get_key(RSA pub)");
    buf.resize(len);
    return buf;
}

RsaKey::RsaKey(RsaKey &&o) noexcept
    : s_(o.s_), obj_(o.obj_), bits_(o.bits_), owns_(o.owns_) {
    o.owns_ = false;
}

RsaKey::~RsaKey() {}

} // namespace se05x
