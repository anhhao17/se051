// csr.cpp
//
// PKCS#10 CSR generation (RSA-2048 / SHA-256) where the private key never
// leaves the SE05x. mbedTLS assembles the ASN.1; the SE produces the signature.

#include "sss.hpp"
#include "log.hpp"

#include <cstring>
#include <functional>
#include <stdexcept>

extern "C" {
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"
#include "mbedtls/pem.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509.h"
}

namespace se05x {
namespace {

using SignFn = std::function<std::vector<uint8_t>(const std::vector<uint8_t> &)>;

#define CHK(expr)                                                                                  \
    do {                                                                                           \
        int _r = (expr);                                                                           \
        if (_r < 0)                                                                                \
            throw CryptoError("mbedtls ASN.1 write failed");                                       \
        len += _r;                                                                                 \
    } while (0)

// Build CertificationRequestInfo (the TBS). Writes backwards into buf.
std::vector<uint8_t> buildCri(const std::string &subjectDn, const std::vector<uint8_t> &spki) {
    std::vector<uint8_t> buf(4096);
    unsigned char *start = buf.data();
    unsigned char *c = buf.data() + buf.size();
    int len = 0;

    mbedtls_asn1_named_data *names = nullptr;
    if (mbedtls_x509_string_to_names(&names, subjectDn.c_str()) != 0)
        throw CryptoError("invalid subject DN: " + subjectDn);

    // attributes [0] -- empty SET
    CHK(mbedtls_asn1_write_len(&c, start, 0));
    CHK(mbedtls_asn1_write_tag(&c, start,
                               MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0));

    // subjectPKInfo -- raw SubjectPublicKeyInfo from the SE
    if (static_cast<size_t>(c - start) < spki.size()) {
        mbedtls_asn1_free_named_data_list(&names);
        throw CryptoError("CSR buffer too small for public key");
    }
    c -= spki.size();
    std::memcpy(c, spki.data(), spki.size());
    len += static_cast<int>(spki.size());

    // subject Name
    {
        int r = mbedtls_x509_write_names(&c, start, names);
        mbedtls_asn1_free_named_data_list(&names);
        if (r < 0)
            throw CryptoError("x509_write_names failed");
        len += r;
    }

    // version INTEGER 0
    CHK(mbedtls_asn1_write_int(&c, start, 0));

    // wrap in SEQUENCE
    CHK(mbedtls_asn1_write_len(&c, start, len));
    CHK(mbedtls_asn1_write_tag(&c, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    return std::vector<uint8_t>(c, c + len);
}

std::string toPem(const std::vector<uint8_t> &der) {
    std::vector<unsigned char> pem(der.size() * 2 + 256);
    size_t olen = 0;
    int r = mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE REQUEST-----\n",
                                     "-----END CERTIFICATE REQUEST-----\n", der.data(), der.size(),
                                     pem.data(), pem.size(), &olen);
    if (r != 0)
        throw CryptoError("pem_write_buffer failed");
    return std::string(reinterpret_cast<char *>(pem.data()), olen);
}

} // namespace

std::string spkiToPem(const std::vector<uint8_t> &spkiDer) {
    std::vector<unsigned char> pem(spkiDer.size() * 2 + 256);
    size_t olen = 0;
    int r = mbedtls_pem_write_buffer("-----BEGIN PUBLIC KEY-----\n", "-----END PUBLIC KEY-----\n",
                                     spkiDer.data(), spkiDer.size(), pem.data(), pem.size(), &olen);
    if (r != 0)
        throw CryptoError("pem_write_buffer(public key) failed");
    return std::string(reinterpret_cast<char *>(pem.data()), olen);
}

namespace {

// Assemble the final CertificationRequest and PEM-encode it.
std::string assembleCsr(const std::vector<uint8_t> &cri, const std::vector<uint8_t> &signature) {
    std::vector<uint8_t> buf(8192);
    unsigned char *start = buf.data();
    unsigned char *c = buf.data() + buf.size();
    int len = 0;

    // signature BIT STRING (0 unused bits)
    CHK(mbedtls_asn1_write_bitstring(&c, start,
                                     reinterpret_cast<const unsigned char *>(signature.data()),
                                     signature.size() * 8));

    // signatureAlgorithm: sha256WithRSAEncryption with explicit NULL params
    {
        const char *oid = MBEDTLS_OID_PKCS1_SHA256;
        size_t oidLen = MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS1_SHA256);
        int r = mbedtls_asn1_write_algorithm_identifier(&c, start, oid, oidLen, 0);
        if (r < 0)
            throw CryptoError("write_algorithm_identifier failed");
        len += r;
    }

    // certificationRequestInfo (raw)
    if (static_cast<size_t>(c - start) < cri.size())
        throw CryptoError("CSR buffer too small for CRI");
    c -= cri.size();
    std::memcpy(c, cri.data(), cri.size());
    len += static_cast<int>(cri.size());

    // wrap SEQUENCE
    CHK(mbedtls_asn1_write_len(&c, start, len));
    CHK(mbedtls_asn1_write_tag(&c, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    return toPem(std::vector<uint8_t>(c, c + len));
}

#undef CHK

std::string makeCsrImpl(const std::string &subjectDn, const std::vector<uint8_t> &spki,
                        const SignFn &sign) {
    LOG_DEBUG("csr: building CRI for subject \"%s\"\n", subjectDn.c_str());
    auto cri = buildCri(subjectDn, spki);

    std::vector<uint8_t> digest(32);
    if (mbedtls_sha256_ret(cri.data(), cri.size(), digest.data(), 0) != 0)
        throw CryptoError("sha256 over CRI failed");

    LOG_DEBUG("csr: signing %zu-byte CRI digest with SE key\n", digest.size());
    auto csr = assembleCsr(cri, sign(digest));
    LOG_DEBUG("csr: assembled %zu-byte PEM CSR\n", csr.size());
    return csr;
}

} // namespace

// For PKCS#11 path: sign receives the full CRI bytes; the callback hashes
// internally via CKM_SHA256_RSA_PKCS and returns raw PKCS#1 v1.5 bytes.
std::string
makeCsrFullSign(const std::string &subjectDn, const std::vector<uint8_t> &spki,
                std::function<std::vector<uint8_t>(const std::vector<uint8_t> &)> sign) {
    LOG_DEBUG("csr: building CRI (PKCS#11 path) for subject \"%s\"\n", subjectDn.c_str());
    auto cri = buildCri(subjectDn, spki);
    LOG_DEBUG("csr: signing %zu-byte CRI via PKCS#11\n", cri.size());
    auto csr = assembleCsr(cri, sign(cri));
    LOG_DEBUG("csr: assembled %zu-byte PEM CSR\n", csr.size());
    return csr;
}

std::string RsaKey::makeCsr(const std::string &subjectDn) {
    auto spki = publicKeyDer();
    return makeCsrImpl(subjectDn, spki,
                       [this](const std::vector<uint8_t> &d) { return this->sign(d); });
}

} // namespace se05x
