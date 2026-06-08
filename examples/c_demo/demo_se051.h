#pragma once

#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <nxEnsure.h>
#include <nxLog_App.h>

/* ---- Key object IDs (demo range 0xEF000xxx, safe per ex_sss_objid.h) ------- */
#define DEMO_KEY_EC_ALICE   0xEF000001u  /* EC P-256 key pair  — sign / verify / CSR */
#define DEMO_KEY_EC_BOB     0xEF000002u  /* EC P-256 key pair  — ECDH peer            */
#define DEMO_KEY_EC_SHARED  0xEF000003u  /* ECDH derived shared secret                */
#define DEMO_KEY_RSA        0xEF000010u  /* RSA 2048 CRT key pair                     */

/* ---- Key bit lengths -------------------------------------------------------- */
#define EC_KEY_BITS          256u        /* NIST P-256 */
#define RSA_KEY_BITS         2048u       /* RSA 2048   */

/* ---- sss_key_object_allocate_handle() keyByteLenMax bounds ----------------- */
#define EC_KEYPAIR_MAX_BYTES  200u       /* P-256 pair DER (actual ~138 B)   */
#define RSA_KEYPAIR_MAX_BYTES 1600u      /* RSA-2048 CRT DER (actual ~1200 B) */

/* ---- Crypto I/O buffer sizes ----------------------------------------------- */
#define EC_PUB_BUF_LEN       200u        /* SubjectPublicKeyInfo DER (P-256 uncompressed) */
#define EC_SIG_BUF_LEN       128u        /* ECDSA-P256 DER signature (max ~72 B)          */
#define ECDH_SHARED_BUF_LEN  64u         /* ECDH shared secret (P-256 = 32 B)             */
#define RSA_PUB_BUF_LEN      512u        /* RSA-2048 SubjectPublicKeyInfo DER (~294 B)    */
#define RSA_SIG_BUF_LEN      256u        /* RSA-2048 signature / ciphertext (= 256 B)    */

sss_status_t demo_rng(ex_sss_boot_ctx_t *pCtx);

sss_status_t demo_ec_keygen(ex_sss_boot_ctx_t *pCtx);
sss_status_t demo_ec_sign_verify(ex_sss_boot_ctx_t *pCtx);
sss_status_t demo_ec_ecdh(ex_sss_boot_ctx_t *pCtx);
sss_status_t demo_ec_csr(ex_sss_boot_ctx_t *pCtx);

sss_status_t demo_rsa_keygen(ex_sss_boot_ctx_t *pCtx);
sss_status_t demo_rsa_sign_verify(ex_sss_boot_ctx_t *pCtx);
sss_status_t demo_rsa_enc_dec(ex_sss_boot_ctx_t *pCtx);
sss_status_t demo_rsa_csr(ex_sss_boot_ctx_t *pCtx);
