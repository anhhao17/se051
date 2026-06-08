/*
 * demo_hmac.c — import a generic secret key, HMAC sign + verify with
 *               SHA-1/256/384/512.
 *
 * Key ID: 0xEF000060.
 */
#include "demo_common.h"

static const CK_BYTE kMsg[]  = "SE051 PKCS#11 HMAC test message";
static const CK_BYTE kKey32[32] = {
    0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,
    0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,
    0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,
    0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,0x0B,
};

int run_hmac(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
    int rc = 0;
    printf("--- HMAC Sign/Verify ---\n");

    CK_BBOOL ck_true  = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;
    CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

    static const char   kLabel[] = "sss:0xEF000060";
    static const CK_BYTE kId[]   = { 0xEF,0x00,0x00,0x60 };
    CK_OBJECT_CLASS cls   = CKO_SECRET_KEY;
    CK_KEY_TYPE     ktype = CKK_GENERIC_SECRET;

    /* Import the HMAC key */
    CK_ATTRIBUTE importTmpl[] = {
        { CKA_CLASS,     &cls,                    sizeof(cls)             },
        { CKA_KEY_TYPE,  &ktype,                  sizeof(ktype)           },
        { CKA_TOKEN,     &ck_true,                sizeof(ck_true)         },
        { CKA_SIGN,      &ck_true,                sizeof(ck_true)         },
        { CKA_VERIFY,    &ck_true,                sizeof(ck_true)         },
        { CKA_SENSITIVE, &ck_false,               sizeof(ck_false)        },
        { CKA_VALUE,     (CK_VOID_PTR)kKey32,     sizeof(kKey32)          },
        { CKA_LABEL,     (CK_VOID_PTR)kLabel,      sizeof(kLabel)-1       },
        { CKA_ID,        (CK_VOID_PTR)kId,         sizeof(kId)            },
    };
    CK_CHECK(p11->C_CreateObject(session, importTmpl,
                                 sizeof(importTmpl)/sizeof(importTmpl[0]),
                                 &hKey));
    printf("  HMAC key imported: hKey=%lu\n", hKey);

    static const struct {
        CK_MECHANISM_TYPE mech;
        const char        *name;
        CK_ULONG           macLen;
    } kAlgs[] = {
        { CKM_SHA_1_HMAC,   "CKM_SHA_1_HMAC",   20 },
        { CKM_SHA256_HMAC,  "CKM_SHA256_HMAC",  32 },
        { CKM_SHA384_HMAC,  "CKM_SHA384_HMAC",  48 },
        { CKM_SHA512_HMAC,  "CKM_SHA512_HMAC",  64 },
    };

    for (size_t i = 0; i < sizeof(kAlgs)/sizeof(kAlgs[0]); i++) {
        CK_MECHANISM mech = { kAlgs[i].mech, NULL_PTR, 0 };
        CK_BYTE mac[64];
        CK_ULONG macLen = sizeof(mac);

        CK_RV rvs = p11->C_SignInit(session, &mech, hKey);
        if (rvs != CKR_OK) {
            printf("  [SKIP] %s: SignInit 0x%08lX\n", kAlgs[i].name, rvs);
            continue;
        }
        rvs = p11->C_Sign(session,
                          (CK_BYTE_PTR)kMsg, (CK_ULONG)(sizeof(kMsg)-1),
                          mac, &macLen);
        if (rvs != CKR_OK) {
            printf("  [FAIL] %s: Sign 0x%08lX\n", kAlgs[i].name, rvs);
            rc = 1;
            goto cleanup;
        }
        char label[40];
        snprintf(label, sizeof(label), "  %s", kAlgs[i].name);
        print_hex(label, mac, macLen);

        CK_RV rvv = p11->C_VerifyInit(session, &mech, hKey);
        if (rvv == CKR_OK)
            rvv = p11->C_Verify(session,
                                (CK_BYTE_PTR)kMsg, (CK_ULONG)(sizeof(kMsg)-1),
                                mac, macLen);
        if (rvv != CKR_OK) {
            printf("  [FAIL] %s verify: 0x%08lX\n", kAlgs[i].name, rvv);
            rc = 1;
            goto cleanup;
        }
        printf("  %s: VALID\n", kAlgs[i].name);
    }

cleanup:
    DESTROY(p11, session, hKey);
    printf("\n");
    return rc;
}
