/* demo_digest.c — C_DigestInit / C_Digest for SHA-1/224/256/384/512 */
#include "demo_common.h"

int run_digest(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
    int rc = 0;
    printf("--- Message Digest ---\n");

    static const CK_BYTE kMsg[] = "SE051 PKCS#11 digest test";
    CK_ULONG msgLen = (CK_ULONG)(sizeof(kMsg) - 1);

    static const struct {
        CK_MECHANISM_TYPE mech;
        const char        *name;
        CK_ULONG           digestLen;
    } kAlgs[] = {
        { CKM_SHA_1,   "SHA-1",   20 },
        { CKM_SHA224,  "SHA-224", 28 },
        { CKM_SHA256,  "SHA-256", 32 },
        { CKM_SHA384,  "SHA-384", 48 },
        { CKM_SHA512,  "SHA-512", 64 },
    };

    CK_BYTE digest[64];

    for (size_t i = 0; i < sizeof(kAlgs)/sizeof(kAlgs[0]); i++) {
        CK_MECHANISM mech = { kAlgs[i].mech, NULL_PTR, 0 };
        CK_ULONG dLen = sizeof(digest);

        CK_RV rv = p11->C_DigestInit(session, &mech);
        if (rv != CKR_OK) {
            printf("  [SKIP] %s: C_DigestInit 0x%08lX\n", kAlgs[i].name, rv);
            continue;
        }
        rv = p11->C_Digest(session, (CK_BYTE_PTR)kMsg, msgLen, digest, &dLen);
        if (rv != CKR_OK) {
            printf("  [FAIL] %s: C_Digest 0x%08lX\n", kAlgs[i].name, rv);
            rc = 1;
            goto cleanup;
        }
        char label[32];
        snprintf(label, sizeof(label), "%s digest", kAlgs[i].name);
        print_hex(label, digest, dLen);
    }

cleanup:
    printf("\n");
    return rc;
}
