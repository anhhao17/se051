#include "demo_se051.h"
#include <string.h>
#include <stdio.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/oid.h>
#include <mbedtls/pem.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509.h>

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
/* RSA key generation                                                   */
/* ------------------------------------------------------------------ */

sss_status_t demo_rsa_keygen(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_object_t keyPair = {0};

    LOG_I("=== RSA Keygen (2048-bit) ===");
    LOG_I("NOTE: RSA 2048 keygen on SE051 may take several seconds...");

    erase_key_if_exists(&pCtx->ks, DEMO_KEY_RSA);

    status = sss_key_object_init(&keyPair, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&keyPair,
        DEMO_KEY_RSA,
        kSSS_KeyPart_Pair,
        kSSS_CipherType_RSA_CRT,
        RSA_KEYPAIR_MAX_BYTES,
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_generate_key(&pCtx->ks, &keyPair, RSA_KEY_BITS, NULL);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("RSA 2048 key pair generated (object ID 0x%08X)", DEMO_KEY_RSA);

cleanup:
    sss_key_object_free(&keyPair);
    if (status != kStatus_SSS_Success)
        LOG_E("RSA keygen FAILED");
    else
        LOG_I("RSA Keygen OK");
    return status;
}

/* ------------------------------------------------------------------ */
/* RSA sign + verify (PKCS#1 v1.5 SHA-256)                             */
/* ------------------------------------------------------------------ */

sss_status_t demo_rsa_sign_verify(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_object_t keyPair = {0};
    sss_digest_t dig_ctx = {0};
    sss_asymmetric_t asym = {0};

    static const uint8_t kMessage[] = "SE051 RSA PKCS1v15 test message";
    uint8_t digest[32] = {0};
    size_t digestLen = sizeof(digest);
    uint8_t sig[RSA_SIG_BUF_LEN] = {0};
    size_t sigLen = sizeof(sig);

    LOG_I("=== RSA Sign / Verify (PKCS#1 v1.5 SHA-256) ===");

    status = sss_key_object_init(&keyPair, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_key_object_get_handle(&keyPair, DEMO_KEY_RSA);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Hash */
    status = sss_digest_context_init(&dig_ctx, &pCtx->session,
                                     kAlgorithm_SSS_SHA256, kMode_SSS_Digest);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_digest_one_go(&dig_ctx, kMessage, sizeof(kMessage) - 1,
                               digest, &digestLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_MAU8_I("SHA-256 digest", digest, digestLen);

    /* Sign */
    status = sss_asymmetric_context_init(&asym, &pCtx->session, &keyPair,
                                         kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256,
                                         kMode_SSS_Sign);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_asymmetric_sign_digest(&asym, digest, digestLen, sig, &sigLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_MAU8_I("RSA signature", sig, sigLen);
    sss_asymmetric_context_free(&asym);

    /* Verify */
    status = sss_asymmetric_context_init(&asym, &pCtx->session, &keyPair,
                                         kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256,
                                         kMode_SSS_Verify);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_asymmetric_verify_digest(&asym, digest, digestLen, sig, sigLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("RSA Sign/Verify OK");

cleanup:
    sss_asymmetric_context_free(&asym);
    sss_digest_context_free(&dig_ctx);
    sss_key_object_free(&keyPair);
    if (status != kStatus_SSS_Success)
        LOG_E("RSA sign/verify FAILED");
    return status;
}

/* ------------------------------------------------------------------ */
/* RSA encrypt + decrypt (OAEP SHA-256)                                 */
/* ------------------------------------------------------------------ */

sss_status_t demo_rsa_enc_dec(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_object_t keyPair = {0};
    sss_asymmetric_t asym = {0};

    static const uint8_t kPlaintext[] = "Hello from SE051!";
    const size_t kPlainLen = sizeof(kPlaintext) - 1;

    uint8_t ciphertext[RSA_SIG_BUF_LEN] = {0};
    size_t ciphertextLen = sizeof(ciphertext);
    uint8_t recovered[RSA_SIG_BUF_LEN] = {0};
    size_t recoveredLen = sizeof(recovered);

    LOG_I("=== RSA Encrypt / Decrypt (OAEP SHA-256) ===");

    status = sss_key_object_init(&keyPair, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_key_object_get_handle(&keyPair, DEMO_KEY_RSA);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Encrypt (uses public key) */
    status = sss_asymmetric_context_init(&asym, &pCtx->session, &keyPair,
                                         kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA256,
                                         kMode_SSS_Encrypt);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_asymmetric_encrypt(&asym, kPlaintext, kPlainLen,
                                    ciphertext, &ciphertextLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_MAU8_I("Ciphertext", ciphertext, ciphertextLen);
    sss_asymmetric_context_free(&asym);

    /* Decrypt (uses private key on SE) */
    status = sss_asymmetric_context_init(&asym, &pCtx->session, &keyPair,
                                         kAlgorithm_SSS_RSAES_PKCS1_OAEP_SHA256,
                                         kMode_SSS_Decrypt);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_asymmetric_decrypt(&asym, ciphertext, ciphertextLen,
                                    recovered, &recoveredLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_MAU8_I("Decrypted", recovered, recoveredLen);

    /* Verify plaintext matches */
    if (recoveredLen != kPlainLen ||
        memcmp(kPlaintext, recovered, kPlainLen) != 0) {
        LOG_E("Decrypted plaintext does NOT match!");
        status = kStatus_SSS_Fail;
        goto cleanup;
    }
    LOG_I("RSA Enc/Dec OK — plaintext matches");

cleanup:
    sss_asymmetric_context_free(&asym);
    sss_key_object_free(&keyPair);
    if (status != kStatus_SSS_Success)
        LOG_E("RSA enc/dec FAILED");
    return status;
}

/* ------------------------------------------------------------------ */
/* RSA CSR (PKCS#10)                                                    */
/* Manual DER construction; signature from SE                           */
/* ------------------------------------------------------------------ */

sss_status_t demo_rsa_csr(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_object_t keyPair = {0};
    sss_asymmetric_t asym = {0};

    /* SE returns SubjectPublicKeyInfo DER directly (same as EC) */
    uint8_t spki[RSA_PUB_BUF_LEN];
    size_t spkiLen = sizeof(spki);
    size_t keyBitLen = 0;

    uint8_t cri_buf[1024];
    uint8_t *cri = NULL;
    size_t criLen = 0;

    uint8_t hash[32];
    uint8_t sig[RSA_SIG_BUF_LEN];
    size_t sigLen = sizeof(sig);

    uint8_t csr_buf[2048];
    uint8_t *csr = NULL;
    size_t csrLen = 0;

    int ret = 0;

    LOG_I("=== RSA CSR (PKCS#10) ===");

    status = sss_key_object_init(&keyPair, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    status = sss_key_object_get_handle(&keyPair, DEMO_KEY_RSA);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Export RSA public key — SE returns SubjectPublicKeyInfo DER directly */
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

    /* Hash CertificationRequestInfo */
    if (mbedtls_sha256_ret(cri, criLen, hash, 0) != 0) {
        status = kStatus_SSS_Fail;
        goto cleanup;
    }

    /* Sign on SE (PKCS#1 v1.5 SHA-256) */
    status = sss_asymmetric_context_init(&asym, &pCtx->session, &keyPair,
                                         kAlgorithm_SSS_RSASSA_PKCS1_V1_5_SHA256,
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

        /* signatureAlgorithm: sha256WithRSAEncryption + explicit NULL params (RFC 4055 §3.2) */
        MBEDTLS_ASN1_CHK_ADD(len,
            mbedtls_asn1_write_algorithm_identifier(
                &p, csr_buf,
                MBEDTLS_OID_PKCS1_SHA256,
                MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS1_SHA256),
                0));

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

    LOG_MAU8_I("RSA CSR DER", csr, csrLen);

    {
        FILE *f = fopen("/tmp/rsa_csr.der", "wb");
        if (f) { fwrite(csr, 1, csrLen, f); fclose(f); }
    }

    {
        uint8_t pem_buf[2048];
        size_t pem_len = 0;
        if (mbedtls_pem_write_buffer(
                "-----BEGIN CERTIFICATE REQUEST-----\n",
                "-----END CERTIFICATE REQUEST-----\n",
                csr, csrLen, pem_buf, sizeof(pem_buf), &pem_len) == 0) {
            LOG_I("RSA CSR PEM:\n%s", (char *)pem_buf);
            FILE *f = fopen("/tmp/rsa_csr.pem", "w");
            if (f) { fwrite(pem_buf, 1, pem_len, f); fclose(f); }
        }
    }

    LOG_I("RSA CSR written to /tmp/rsa_csr.der and /tmp/rsa_csr.pem");
    LOG_I("Verify: openssl req -in /tmp/rsa_csr.pem -noout -text");
    LOG_I("RSA CSR OK");
    status = kStatus_SSS_Success;

cleanup:
    sss_asymmetric_context_free(&asym);
    sss_key_object_free(&keyPair);
    if (status != kStatus_SSS_Success)
        LOG_E("RSA CSR FAILED");
    return status;
}
