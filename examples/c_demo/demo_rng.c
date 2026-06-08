#include "demo_se051.h"

sss_status_t demo_rng(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_rng_context_t rng = {0};
    uint8_t random_data[32] = {0};

    LOG_I("=== RNG Demo ===");

    status = sss_rng_context_init(&rng, &pCtx->session);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_rng_get_random(&rng, random_data, sizeof(random_data));
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_I("SE RNG (32 bytes)", random_data, sizeof(random_data));
    LOG_I("RNG OK");

cleanup:
    sss_rng_context_free(&rng);
    if (status != kStatus_SSS_Success)
        LOG_E("RNG demo FAILED");
    return status;
}
