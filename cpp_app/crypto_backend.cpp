/**
 * @file crypto_backend.cpp
 * @brief Pkcs11Backend and SssBackend implementations.
 *
 * Both classes forward calls to their wrapped context (Pkcs11Ctx / se05x::*)
 * and handle the algorithm-specific differences (e.g. PKCS#11 hashes the message
 * internally via CKM_SHA256_RSA_PKCS, while the SSS path pre-computes SHA-256).
 */

#include "crypto_backend.hpp"
#include "log.hpp"
#include "se05x_object_store.hpp"
#include "se05x_provision.hpp"

extern "C" {
#include "mbedtls/sha256.h"
}

namespace {

std::vector<uint8_t> sha256(const std::vector<uint8_t> &in) {
    std::vector<uint8_t> out(32);
    mbedtls_sha256_ret(in.data(), in.size(), out.data(), 0);
    return out;
}

} // namespace

Pkcs11Backend::Pkcs11Backend(const std::string &libPath) : ctx_(libPath) {}

std::vector<uint8_t> Pkcs11Backend::getRandom(size_t n) {
    return ctx_.getRandom(n);
}

bool Pkcs11Backend::keyExists(uint32_t id) {
    return ctx_.findKey(id, CKO_PRIVATE_KEY) != CK_INVALID_HANDLE;
}

void Pkcs11Backend::deleteKey(uint32_t id) {
    ctx_.destroyObject(ctx_.findKey(id, CKO_PRIVATE_KEY));
    ctx_.destroyObject(ctx_.findKey(id, CKO_PUBLIC_KEY));
}

void Pkcs11Backend::generateKey(uint32_t id, se05x::RsaBits bits, se05x::KeyPolicy /*policy*/) {
    LOG_DEBUG("pkcs11: genRsaKeyPair id=0x%08X bits=%lu\n", id, static_cast<unsigned long>(bits));
    ctx_.genRsaKeyPair(id, static_cast<CK_ULONG>(bits));
}

std::vector<uint8_t> Pkcs11Backend::getSpki(uint32_t id) {
    return ctx_.getSpki(id);
}

std::vector<uint8_t> Pkcs11Backend::sign(uint32_t id, const std::vector<uint8_t> &msg) {
    auto h = ctx_.findKey(id, CKO_PRIVATE_KEY);
    if (h == CK_INVALID_HANDLE)
        throw std::runtime_error("RSA private key not found");
    return ctx_.signRsa(h, msg);
}

bool Pkcs11Backend::verify(uint32_t id, const std::vector<uint8_t> &msg,
                           const std::vector<uint8_t> &sig) {
    auto h = ctx_.findKey(id, CKO_PUBLIC_KEY);
    if (h == CK_INVALID_HANDLE)
        throw std::runtime_error("RSA public key not found");
    return ctx_.verifyRsa(h, msg, sig);
}

std::string Pkcs11Backend::makeCsr(uint32_t id, const std::string &subjectDn) {
    auto spki = ctx_.getSpki(id);
    auto hPriv = ctx_.findKey(id, CKO_PRIVATE_KEY);
    if (hPriv == CK_INVALID_HANDLE)
        throw std::runtime_error("RSA private key not found");
    return se05x::makeCsrFullSign(subjectDn, spki, [this, hPriv](const std::vector<uint8_t> &cri) {
        return ctx_.signRsa(hPriv, cri);
    });
}

SssBackend::SssBackend(se05x::Session &session) : session_(session) {}

std::vector<uint8_t> SssBackend::getRandom(size_t n) {
    return se05x::getRandom(session_, n);
}

bool SssBackend::keyExists(uint32_t id) {
    return se05x::objectExists(session_, id);
}

void SssBackend::deleteKey(uint32_t id) {
    if (se05x::objectExists(session_, id))
        se05x::eraseObject(session_, id);
}

void SssBackend::generateKey(uint32_t id, se05x::RsaBits bits, se05x::KeyPolicy policy) {
    LOG_DEBUG("sss: RsaKey::generate id=0x%08X bits=%zu\n", id, static_cast<size_t>(bits));
    se05x::generateKeyWithPolicy(session_, id, bits, policy);
}

std::vector<uint8_t> SssBackend::getSpki(uint32_t id) {
    return se05x::RsaKey::open(session_, id).publicKeyDer();
}

std::vector<uint8_t> SssBackend::sign(uint32_t id, const std::vector<uint8_t> &msg) {
    return se05x::RsaKey::open(session_, id).sign(sha256(msg));
}

bool SssBackend::verify(uint32_t id, const std::vector<uint8_t> &msg,
                        const std::vector<uint8_t> &sig) {
    return se05x::RsaKey::open(session_, id).verify(sha256(msg), sig);
}

std::string SssBackend::makeCsr(uint32_t id, const std::string &subjectDn) {
    return se05x::RsaKey::open(session_, id).makeCsr(subjectDn);
}
