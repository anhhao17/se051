#include "demo_se051.h"

static ex_sss_boot_ctx_t gCtx;

#define EX_SSS_BOOT_PCONTEXT      (&gCtx)
#define EX_SSS_BOOT_DO_ERASE      0   /* SE05x keys managed per-function */
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

#define RUN(fn, label)                                          \
    do {                                                        \
        LOG_I("--------------------------------------------"); \
        status = (fn);                                          \
        if (status != kStatus_SSS_Success) {                    \
            LOG_E("DEMO ABORTED at: " label);                   \
            goto cleanup;                                       \
        }                                                       \
    } while (0)

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Success;

    LOG_I("SE051 Crypto Demo — starting");

    RUN(demo_rng(pCtx),             "RNG");
    RUN(demo_ec_keygen(pCtx),       "EC keygen");
    RUN(demo_ec_sign_verify(pCtx),  "EC sign/verify");
    RUN(demo_ec_ecdh(pCtx),         "EC ECDH");
    RUN(demo_ec_csr(pCtx),          "EC CSR");
    RUN(demo_rsa_keygen(pCtx),      "RSA keygen");
    RUN(demo_rsa_sign_verify(pCtx), "RSA sign/verify");
    RUN(demo_rsa_enc_dec(pCtx),     "RSA enc/dec");
    RUN(demo_rsa_csr(pCtx),         "RSA CSR");

    LOG_I("============================================");
    LOG_I("SE051 Crypto Demo — ALL DEMOS PASSED");

cleanup:
    if (status != kStatus_SSS_Success)
        LOG_E("SE051 Crypto Demo — FAILED");
    return status;
}
