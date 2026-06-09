/**
 * @file pkcs11_ctx.cpp
 * @brief Implementation of Pkcs11Ctx - RAII PKCS#11 session over NXP SE05x.
 */

#include "pkcs11_ctx.hpp"

#include <array>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <vector>

extern "C" {
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
}

Pkcs11Error::Pkcs11Error(const std::string &msg, CK_RV rv)
    : std::runtime_error([&] {
          char buf[64];
          std::snprintf(buf, sizeof(buf), ": CKR 0x%08lX", static_cast<unsigned long>(rv));
          return msg + buf;
      }()),
      rv_(rv) {}

static void ckCheck(CK_RV rv, const char *where) {
    if (rv != CKR_OK)
        throw Pkcs11Error(std::string("PKCS#11 ") + where + " failed", rv);
}

Pkcs11Ctx::Pkcs11Ctx(const std::string &libPath) {
    lib_ = dlopen(libPath.c_str(), RTLD_NOW);
    if (!lib_)
        throw Pkcs11Error(std::string("dlopen(") + libPath + "): " + dlerror());

    auto getFnList = reinterpret_cast<CK_C_GetFunctionList>(dlsym(lib_, "C_GetFunctionList"));
    if (!getFnList) {
        dlclose(lib_);
        lib_ = nullptr;
        throw Pkcs11Error("C_GetFunctionList symbol not found in " + libPath);
    }

    CK_RV rv = getFnList(&p11_);
    if (rv != CKR_OK || !p11_) {
        dlclose(lib_);
        lib_ = nullptr;
        throw Pkcs11Error("C_GetFunctionList() returned error", rv);
    }

    ckCheck(p11_->C_Initialize(nullptr), "C_Initialize");

    // Enumerate slots that have a token present and use the first one.
    CK_ULONG slotCount = 0;
    ckCheck(p11_->C_GetSlotList(CK_TRUE, nullptr, &slotCount), "C_GetSlotList (count)");
    if (slotCount == 0)
        throw Pkcs11Error("No PKCS#11 slots with a token - is the SE connected?");

    std::vector<CK_SLOT_ID> slots(slotCount);
    ckCheck(p11_->C_GetSlotList(CK_TRUE, slots.data(), &slotCount), "C_GetSlotList");

    ckCheck(p11_->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr,
                                &hSess_),
            "C_OpenSession");
}

Pkcs11Ctx::~Pkcs11Ctx() {
    if (hSess_ != CK_INVALID_HANDLE && p11_) {
        p11_->C_CloseSession(hSess_);
        hSess_ = CK_INVALID_HANDLE;
    }
    if (p11_) {
        p11_->C_Finalize(nullptr);
        p11_ = nullptr;
    }
    if (lib_) {
        dlclose(lib_);
        lib_ = nullptr;
    }
}

std::string Pkcs11Ctx::label(uint32_t id) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "sss:0x%08X", id);
    return buf;
}

std::array<CK_BYTE, 4> Pkcs11Ctx::idBytes(uint32_t id) {
    return {{
        static_cast<CK_BYTE>((id >> 24) & 0xFF),
        static_cast<CK_BYTE>((id >> 16) & 0xFF),
        static_cast<CK_BYTE>((id >> 8) & 0xFF),
        static_cast<CK_BYTE>(id & 0xFF),
    }};
}

std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE> Pkcs11Ctx::genRsaKeyPair(uint32_t id, CK_ULONG bits) {
    auto lbl = label(id);
    auto idb = idBytes(id);
    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;
    static const CK_BYTE kPubExp[] = {0x01, 0x00, 0x01}; // 65537

    CK_ATTRIBUTE pubTmpl[] = {
        {CKA_TOKEN, &ck_true, sizeof(ck_true)},
        {CKA_VERIFY, &ck_true, sizeof(ck_true)},
        {CKA_ENCRYPT, &ck_true, sizeof(ck_true)},
        {CKA_EXTRACTABLE, &ck_false, sizeof(ck_false)},
        {CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, const_cast<CK_BYTE *>(kPubExp), sizeof(kPubExp)},
        {CKA_LABEL, const_cast<char *>(lbl.c_str()), lbl.size()},
        {CKA_ID, idb.data(), idb.size()},
    };
    CK_ATTRIBUTE privTmpl[] = {
        {CKA_TOKEN, &ck_true, sizeof(ck_true)},
        {CKA_SENSITIVE, &ck_true, sizeof(ck_true)},
        {CKA_SIGN, &ck_true, sizeof(ck_true)},
        {CKA_DECRYPT, &ck_true, sizeof(ck_true)},
        {CKA_EXTRACTABLE, &ck_false, sizeof(ck_false)},
        {CKA_LABEL, const_cast<char *>(lbl.c_str()), lbl.size()},
        {CKA_ID, idb.data(), idb.size()},
    };
    CK_MECHANISM mechKG = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
    CK_OBJECT_HANDLE hPub = CK_INVALID_HANDLE, hPriv = CK_INVALID_HANDLE;

    ckCheck(p11_->C_GenerateKeyPair(hSess_, &mechKG, pubTmpl, sizeof(pubTmpl) / sizeof(pubTmpl[0]),
                                    privTmpl, sizeof(privTmpl) / sizeof(privTmpl[0]), &hPub,
                                    &hPriv),
            "C_GenerateKeyPair(RSA)");
    return {hPub, hPriv};
}

CK_OBJECT_HANDLE Pkcs11Ctx::findKey(uint32_t id, CK_OBJECT_CLASS cls) {
    auto lbl = label(id);
    CK_ATTRIBUTE tmpl[] = {
        {CKA_CLASS, &cls, sizeof(cls)},
        {CKA_LABEL, const_cast<char *>(lbl.c_str()), lbl.size()},
    };

    if (p11_->C_FindObjectsInit(hSess_, tmpl, 2) != CKR_OK)
        return CK_INVALID_HANDLE;

    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    CK_ULONG count = 0;
    p11_->C_FindObjects(hSess_, &h, 1, &count);
    p11_->C_FindObjectsFinal(hSess_);
    return (count > 0) ? h : CK_INVALID_HANDLE;
}

void Pkcs11Ctx::destroyObject(CK_OBJECT_HANDLE h) {
    if (h != CK_INVALID_HANDLE)
        p11_->C_DestroyObject(hSess_, h);
}

std::vector<uint8_t> Pkcs11Ctx::signRsa(CK_OBJECT_HANDLE hPriv, const std::vector<uint8_t> &msg) {
    CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS, nullptr, 0};
    ckCheck(p11_->C_SignInit(hSess_, &mech, hPriv), "C_SignInit(RSA)");

    // Two-step: query output size, then sign.
    CK_ULONG sigLen = 0;
    ckCheck(p11_->C_Sign(hSess_, const_cast<CK_BYTE *>(msg.data()),
                         static_cast<CK_ULONG>(msg.size()), nullptr, &sigLen),
            "C_Sign(RSA, query)");

    std::vector<uint8_t> sig(sigLen);
    ckCheck(p11_->C_Sign(hSess_, const_cast<CK_BYTE *>(msg.data()),
                         static_cast<CK_ULONG>(msg.size()), sig.data(), &sigLen),
            "C_Sign(RSA)");
    sig.resize(sigLen);
    return sig;
}

bool Pkcs11Ctx::verifyRsa(CK_OBJECT_HANDLE hPub, const std::vector<uint8_t> &msg,
                          const std::vector<uint8_t> &sig) {
    CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS, nullptr, 0};
    if (p11_->C_VerifyInit(hSess_, &mech, hPub) != CKR_OK)
        return false;
    CK_RV rv =
        p11_->C_Verify(hSess_, const_cast<CK_BYTE *>(msg.data()), static_cast<CK_ULONG>(msg.size()),
                       const_cast<CK_BYTE *>(sig.data()), static_cast<CK_ULONG>(sig.size()));
    return (rv == CKR_OK);
}

std::vector<uint8_t> Pkcs11Ctx::encryptRsa(CK_OBJECT_HANDLE hPub,
                                           const std::vector<uint8_t> &plain) {
    CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, nullptr, 0};
    CK_MECHANISM mech = {CKM_RSA_PKCS_OAEP, &params, sizeof(params)};
    ckCheck(p11_->C_EncryptInit(hSess_, &mech, hPub), "C_EncryptInit");

    CK_ULONG outLen = 0;
    ckCheck(p11_->C_Encrypt(hSess_, const_cast<CK_BYTE *>(plain.data()),
                            static_cast<CK_ULONG>(plain.size()), nullptr, &outLen),
            "C_Encrypt (query)");
    std::vector<uint8_t> out(outLen);
    ckCheck(p11_->C_Encrypt(hSess_, const_cast<CK_BYTE *>(plain.data()),
                            static_cast<CK_ULONG>(plain.size()), out.data(), &outLen),
            "C_Encrypt");
    out.resize(outLen);
    return out;
}

std::vector<uint8_t> Pkcs11Ctx::decryptRsa(CK_OBJECT_HANDLE hPriv,
                                           const std::vector<uint8_t> &cipher) {
    CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, nullptr, 0};
    CK_MECHANISM mech = {CKM_RSA_PKCS_OAEP, &params, sizeof(params)};
    ckCheck(p11_->C_DecryptInit(hSess_, &mech, hPriv), "C_DecryptInit");

    CK_ULONG outLen = 0;
    ckCheck(p11_->C_Decrypt(hSess_, const_cast<CK_BYTE *>(cipher.data()),
                            static_cast<CK_ULONG>(cipher.size()), nullptr, &outLen),
            "C_Decrypt (query)");
    std::vector<uint8_t> out(outLen);
    ckCheck(p11_->C_Decrypt(hSess_, const_cast<CK_BYTE *>(cipher.data()),
                            static_cast<CK_ULONG>(cipher.size()), out.data(), &outLen),
            "C_Decrypt");
    out.resize(outLen);
    return out;
}

std::vector<uint8_t> Pkcs11Ctx::getRandom(size_t n) {
    std::vector<uint8_t> out(n);
    ckCheck(p11_->C_GenerateRandom(hSess_, out.data(), static_cast<CK_ULONG>(n)),
            "C_GenerateRandom");
    return out;
}

std::vector<uint8_t> Pkcs11Ctx::getSpki(uint32_t id) {
    CK_OBJECT_HANDLE hPub = findKey(id, CKO_PUBLIC_KEY);
    if (hPub == CK_INVALID_HANDLE)
        throw Pkcs11Error("RSA public key not found", CKR_OBJECT_HANDLE_INVALID);

    // Two-pass C_GetAttributeValue: first pass queries lengths.
    auto readAttr = [&](CK_ATTRIBUTE_TYPE type) {
        CK_ATTRIBUTE attr = {type, nullptr, 0};
        CK_RV rv = p11_->C_GetAttributeValue(hSess_, hPub, &attr, 1);
        if (rv != CKR_OK || attr.ulValueLen == 0)
            throw Pkcs11Error("C_GetAttributeValue (size query) failed", rv);
        std::vector<CK_BYTE> val(attr.ulValueLen);
        attr.pValue = val.data();
        rv = p11_->C_GetAttributeValue(hSess_, hPub, &attr, 1);
        if (rv != CKR_OK)
            throw Pkcs11Error("C_GetAttributeValue (value) failed", rv);
        return val;
    };

    auto modulus = readAttr(CKA_MODULUS);
    auto exponent = readAttr(CKA_PUBLIC_EXPONENT);

    // Build SubjectPublicKeyInfo DER via mbedTLS.
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    int r = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (r != 0) {
        mbedtls_pk_free(&pk);
        throw Pkcs11Error("mbedtls_pk_setup failed");
    }

    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);
    r = mbedtls_mpi_read_binary(&rsa->N, modulus.data(), modulus.size());
    r |= mbedtls_mpi_read_binary(&rsa->E, exponent.data(), exponent.size());
    rsa->len = modulus.size();
    if (r != 0) {
        mbedtls_pk_free(&pk);
        throw Pkcs11Error("MPI read_binary failed");
    }

    // pk_write_pubkey_der writes at the END of the supplied buffer.
    std::vector<uint8_t> buf(modulus.size() + 128);
    int n = mbedtls_pk_write_pubkey_der(&pk, buf.data(), buf.size());
    mbedtls_pk_free(&pk);
    if (n <= 0)
        throw Pkcs11Error("mbedtls_pk_write_pubkey_der failed");

    return std::vector<uint8_t>(buf.end() - n, buf.end());
}
