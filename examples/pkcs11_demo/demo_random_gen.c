/* demo_random_gen.c — C_GenerateRandom for several buffer sizes */
#include "demo_common.h"

int run_random_gen(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
    int rc = 0;
    printf("--- Hardware RNG ---\n");

    static const CK_ULONG kSizes[] = { 1, 16, 32, 64, 128, 512, 1024 };
    CK_BYTE buf[1024];

    for (size_t i = 0; i < sizeof(kSizes)/sizeof(kSizes[0]); i++) {
        CK_ULONG len = kSizes[i];
        memset(buf, 0, len);
        CK_CHECK(p11->C_GenerateRandom(session, buf, len));
        char label[32];
        snprintf(label, sizeof(label), "random %4lu bytes", len);
        print_hex(label, buf, len);
    }

cleanup:
    printf("\n");
    return rc;
}
