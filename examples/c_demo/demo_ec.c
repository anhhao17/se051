#include "demo_se051.h"
#include <string.h>
#include <stdio.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/oid.h>
#include <mbedtls/pem.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509.h>

/* Erase a key object by ID if it exists (ignores errors) */
static void erase_key_if_exists(sss_key_store_t *ks, uint32_t keyId)
{
    sss_object_t obj = {0};
    if (sss_key_object_init(&obj, ks) != kStatus_SSS_Success)
        return;
    if (sss_key_object_get_handle(&obj, keyId) == kStatus_SSS_Success)
        sss_key_store_erase_key(ks, &obj);
    sss_key_object_free(&obj);
}

/* ------------------------------------------------------------------ */
/* EC key generation                                                    */
/* ------------------------------------------------------------------ */

sss_status_t demo_ec_keygen(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_object_t keyPair = {0};
    uint8_t pubBuf[EC_PUB_BUF_LEN];
    size_t pubLen = sizeof(pubBuf);
    size_t keyBitLen = 0;

    LOG_I("=== EC Keygen (P-256) ===");

    erase_key_if_exists(&pCtx->ks, DEMO_KEY_EC_ALICE);

    status = sss_key_object_init(&keyPair, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&keyPair,
        DEMO_KEY_EC_ALICE,
        kSSS_KeyPart_Pair,
        kSSS_CipherType_EC_NIST_P,
        EC_KEYPAIR_MAX_BYTES,
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_generate_key(&pCtx->ks, &keyPair, EC_KEY_BITS, NULL);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("EC key pair generated (object ID 0x%08X)", DEMO_KEY_EC_ALICE);

    /* Export and display the public key (SubjectPublicKeyInfo DER) */
    status = sss_key_store_get_key(&pCtx->ks, &keyPair, pubBuf, &pubLen, &keyBitLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_MAU8_I("EC public key (SPKI DER)", pubBuf, pubLen);
    LOG_I("EC Keygen OK");

cleanup:
    sss_key_object_free(&keyPair);
    if (status != kStatus_SSS_Success)
        LOG_E("EC keygen FAILED");
    return status;
}

/* ------------------------------------------------------------------ */
/* EC sign + verify                                                     */
/* ------------------------------------------------------------------ */

sss_status_t demo_ec_sign_verify(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_object_t keyPair = {0};
    sss_digest_t dig_ctx = {0};
    sss_asymmetric_t asym = {0};

    static const uint8_t kMessage[] = "SE051 ECDSA test message";
    uint8_t digest[32] = {0};
    size_t digestLen = sizeof(digest);
    uint8_t sig[EC_SIG_BUF_LEN] = {0};
    size_t sigLen = sizeof(sig);

    LOG_I("=== EC Sign / Verify ===");

    /* Open the Alice key pair generated in ec_keygen */
    status = sss_key_object_init(&keyPair, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_key_object_get_handle(&keyPair, DEMO_KEY_EC_ALICE);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Hash the message on the SE */
    status = sss_digest_context_init(&dig_ctx, &pCtx->session,
                                     kAlgorithm_SSS_SHA256, kMode_SSS_Digest);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_digest_one_go(&dig_ctx, kMessage, sizeof(kMessage) - 1,
                               digest, &digestLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_MAU8_I("SHA-256 digest", digest, digestLen);

    /* Sign on SE */
    status = sss_asymmetric_context_init(&asym, &pCtx->session, &keyPair,
                                         kAlgorithm_SSS_ECDSA_SHA256,
                                         kMode_SSS_Sign);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_asymmetric_sign_digest(&asym, digest, digestLen, sig, &sigLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_MAU8_I("ECDSA signature", sig, sigLen);
    sss_asymmetric_context_free(&asym);

    /* Verify on SE */
    status = sss_asymmetric_context_init(&asym, &pCtx->session, &keyPair,
                                         kAlgorithm_SSS_ECDSA_SHA256,
                                         kMode_SSS_Verify);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_asymmetric_verify_digest(&asym, digest, digestLen, sig, sigLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("EC Sign/Verify OK");

cleanup:
    sss_asymmetric_context_free(&asym);
    sss_digest_context_free(&dig_ctx);
    sss_key_object_free(&keyPair);
    if (status != kStatus_SSS_Success)
        LOG_E("EC sign/verify FAILED");
    return status;
}

/* ------------------------------------------------------------------ */
/* ECDH key agreement (both parties on SE)                              */
/* ------------------------------------------------------------------ */

sss_status_t demo_ec_ecdh(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_object_t alice = {0};
    sss_object_t bob   = {0};
    sss_object_t shared = {0};
    sss_derive_key_t dctx = {0};
    uint8_t sharedBuf[ECDH_SHARED_BUF_LEN] = {0};
    size_t sharedLen = sizeof(sharedBuf);
    size_t keyBitLen = 0;

    LOG_I("=== ECDH Key Agreement ===");

    /* Alice's key pair is already in DEMO_KEY_EC_ALICE from ec_keygen */
    status = sss_key_object_init(&alice, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_key_object_get_handle(&alice, DEMO_KEY_EC_ALICE);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Generate Bob's key pair */
    erase_key_if_exists(&pCtx->ks, DEMO_KEY_EC_BOB);
    status = sss_key_object_init(&bob, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_key_object_allocate_handle(&bob,
        DEMO_KEY_EC_BOB,
        kSSS_KeyPart_Pair,
        kSSS_CipherType_EC_NIST_P,
        EC_KEYPAIR_MAX_BYTES,
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_key_store_generate_key(&pCtx->ks, &bob, EC_KEY_BITS, NULL);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("Bob key pair generated (ID 0x%08X)", DEMO_KEY_EC_BOB);

    /* Allocate slot for derived shared secret */
    erase_key_if_exists(&pCtx->ks, DEMO_KEY_EC_SHARED);
    status = sss_key_object_init(&shared, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_key_object_allocate_handle(&shared,
        DEMO_KEY_EC_SHARED,
        kSSS_KeyPart_Default,
        kSSS_CipherType_AES,  /* shared secret stored as binary/AES slot */
        32,
        kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* ECDH: Alice (private) x Bob (public) → shared secret */
    status = sss_derive_key_context_init(&dctx, &pCtx->session, &alice,
                                         kAlgorithm_SSS_ECDH,
                                         kMode_SSS_ComputeSharedSecret);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_derive_key_dh(&dctx, &bob, &shared);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("ECDH computed");

    /* Export shared secret (may fail if SE policy prevents AES key export) */
    if (sss_key_store_get_key(&pCtx->ks, &shared,
                               sharedBuf, &sharedLen, &keyBitLen)
            == kStatus_SSS_Success) {
        LOG_MAU8_I("Shared secret", sharedBuf, sharedLen);
    } else {
        LOG_I("Shared secret stored on SE (not exportable)");
    }
    LOG_I("ECDH OK");

cleanup:
    sss_derive_key_context_free(&dctx);
    sss_key_object_free(&shared);
    sss_key_object_free(&bob);
    sss_key_object_free(&alice);
    if (status != kStatus_SSS_Success)
        LOG_E("ECDH FAILED");
    return status;
}

/* ------------------------------------------------------------------ */
/* EC CSR (PKCS#10)                                                     */
/* Manual DER construction; signature from SE                           */
/* ------------------------------------------------------------------ */

sss_status_t demo_ec_csr(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_object_t keyPair = {0};
    sss_asymmetric_t asym = {0};

    uint8_t spki[EC_PUB_BUF_LEN];
    size_t spkiLen = sizeof(spki);
    size_t keyBitLen = 0;

    uint8_t cri_buf[512];
    uint8_t *cri = NULL;
    size_t criLen = 0;

    uint8_t hash[32];
    uint8_t sig[EC_SIG_BUF_LEN];
    size_t sigLen = sizeof(sig);

    uint8_t csr_buf[1024];
    uint8_t *csr = NULL;
    size_t csrLen = 0;

    int ret = 0;

    LOG_I("=== EC CSR (PKCS#10) ===");

    status = sss_key_object_init(&keyPair, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_key_object_get_handle(&keyPair, DEMO_KEY_EC_ALICE);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Export public key — SE returns SubjectPublicKeyInfo DER */
    status = sss_key_store_get_key(&pCtx->ks, &keyPair, spki, &spkiLen, &keyBitLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* ------ Build CertificationRequestInfo (written backwards) ------ */
    {
        uint8_t *p = cri_buf + sizeof(cri_buf);
        size_t len = 0;
        mbedtls_asn1_named_data *names = NULL;
        int r;

        /* [0] IMPLICIT {} — empty attributes */
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, cri_buf, 0));
        MBEDTLS_ASN1_CHK_ADD(len,
            mbedtls_asn1_write_tag(&p, cri_buf,
                MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0));

        /* SubjectPublicKeyInfo (raw DER from SE) */
        MBEDTLS_ASN1_CHK_ADD(len,
            mbedtls_asn1_write_raw_buffer(&p, cri_buf, spki, spkiLen));

        /* Subject Name — parsed and encoded by mbedTLS */
        if (mbedtls_x509_string_to_names(&names, "CN=SE051-Demo") != 0) {
            status = kStatus_SSS_Fail;
            goto cleanup;
        }
        r = mbedtls_x509_write_names(&p, cri_buf, names);
        mbedtls_asn1_free_named_data_list(&names);
        if (r < 0) { status = kStatus_SSS_Fail; goto cleanup; }
        len += (size_t)r;

        /* version INTEGER 0 */
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(&p, cri_buf, 0));

        /* SEQUENCE wrapper */
        size_t content_len = len;
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, cri_buf, content_len));
        MBEDTLS_ASN1_CHK_ADD(len,
            mbedtls_asn1_write_tag(&p, cri_buf,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

        cri    = p;
        criLen = len;
        (void)ret;
    }

    /* Hash the CertificationRequestInfo */
    if (mbedtls_sha256_ret(cri, criLen, hash, 0) != 0) {
        status = kStatus_SSS_Fail;
        goto cleanup;
    }

    /* Sign hash on SE */
    status = sss_asymmetric_context_init(&asym, &pCtx->session, &keyPair,
                                         kAlgorithm_SSS_ECDSA_SHA256,
                                         kMode_SSS_Sign);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_asymmetric_sign_digest(&asym, hash, sizeof(hash), sig, &sigLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    sss_asymmetric_context_free(&asym);

    /* ------ Assemble CertificationRequest (written backwards) ------ */
    {
        uint8_t *p = csr_buf + sizeof(csr_buf);
        size_t len = 0;

        /* BIT STRING { sig } */
        MBEDTLS_ASN1_CHK_ADD(len,
            mbedtls_asn1_write_bitstring(&p, csr_buf, sig, sigLen * 8));

        /* signatureAlgorithm: ecdsa-with-SHA256, no parameters (RFC 5480 §3) */
        MBEDTLS_ASN1_CHK_ADD(len,
            mbedtls_asn1_write_algorithm_identifier_ext(
                &p, csr_buf,
                MBEDTLS_OID_ECDSA_SHA256,
                MBEDTLS_OID_SIZE(MBEDTLS_OID_ECDSA_SHA256),
                0, 0));

        /* CertificationRequestInfo */
        MBEDTLS_ASN1_CHK_ADD(len,
            mbedtls_asn1_write_raw_buffer(&p, csr_buf, cri, criLen));

        /* Outer SEQUENCE */
        size_t content_len = len;
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, csr_buf, content_len));
        MBEDTLS_ASN1_CHK_ADD(len,
            mbedtls_asn1_write_tag(&p, csr_buf,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

        csr    = p;
        csrLen = len;
        (void)ret;
    }

    LOG_MAU8_I("EC CSR DER", csr, csrLen);

    {
        FILE *f = fopen("/tmp/ec_csr.der", "wb");
        if (f) { fwrite(csr, 1, csrLen, f); fclose(f); }
    }

    {
        uint8_t pem_buf[1024];
        size_t pem_len = 0;
        if (mbedtls_pem_write_buffer(
                "-----BEGIN CERTIFICATE REQUEST-----\n",
                "-----END CERTIFICATE REQUEST-----\n",
                csr, csrLen, pem_buf, sizeof(pem_buf), &pem_len) == 0) {
            LOG_I("EC CSR PEM:\n%s", (char *)pem_buf);
            FILE *f = fopen("/tmp/ec_csr.pem", "w");
            if (f) { fwrite(pem_buf, 1, pem_len, f); fclose(f); }
        }
    }

    LOG_I("EC CSR written to /tmp/ec_csr.der and /tmp/ec_csr.pem");
    LOG_I("Verify: openssl req -in /tmp/ec_csr.pem -noout -text");
    LOG_I("EC CSR OK");
    status = kStatus_SSS_Success;

cleanup:
    sss_asymmetric_context_free(&asym);
    sss_key_object_free(&keyPair);
    if (status != kStatus_SSS_Success)
        LOG_E("EC CSR FAILED");
    return status;
}
