/* demo_sym_key_gen.c — AES key generation (128/192/256-bit) + generic secret key */
#include "demo_common.h"

int run_sym_key_gen(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
    int rc = 0;
    printf("--- Symmetric Key Generation ---\n");

    CK_BBOOL ck_true  = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;

    static const struct {
        CK_ULONG    len;        /* key length in bytes */
        const char *label;
        CK_BYTE     id[4];
    } kAesKeys[] = {
        { 16, "sss:0xEF0000B0", { 0xEF,0x00,0x00,0xB0 } }, /* AES-128 */
        { 24, "sss:0xEF0000B1", { 0xEF,0x00,0x00,0xB1 } }, /* AES-192 */
        { 32, "sss:0xEF0000B2", { 0xEF,0x00,0x00,0xB2 } }, /* AES-256 */
    };

    for (size_t i = 0; i < sizeof(kAesKeys)/sizeof(kAesKeys[0]); i++) {
        CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
        CK_ULONG kLen = kAesKeys[i].len;

        CK_ATTRIBUTE tmpl[] = {
            { CKA_TOKEN,     &ck_true,                                sizeof(ck_true)       },
            { CKA_ENCRYPT,   &ck_true,                                sizeof(ck_true)       },
            { CKA_DECRYPT,   &ck_true,                                sizeof(ck_true)       },
            { CKA_SENSITIVE, &ck_false,                               sizeof(ck_false)      },
            { CKA_VALUE_LEN, &kLen,                                   sizeof(kLen)          },
            { CKA_LABEL,     (CK_VOID_PTR)kAesKeys[i].label,         strlen(kAesKeys[i].label) },
            { CKA_ID,        (CK_VOID_PTR)kAesKeys[i].id,            sizeof(kAesKeys[i].id)},
        };
        CK_MECHANISM mech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };

        printf("  AES-%lu (%s):\n", kLen * 8, kAesKeys[i].label);
        CK_CHECK(p11->C_GenerateKey(session, &mech, tmpl,
                                    sizeof(tmpl)/sizeof(tmpl[0]), &hKey));
        printf("    hKey = %lu\n", hKey);
        DESTROY(p11, session, hKey);
    }

    /* Generic secret key — useful as HMAC key material */
    {
        CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
        static const char kLabel[] = "sss:0xEF0000B3";
        static const CK_BYTE kId[] = { 0xEF,0x00,0x00,0xB3 };
        CK_ULONG kLen = 32;

        CK_ATTRIBUTE tmpl[] = {
            { CKA_TOKEN,     &ck_true,  sizeof(ck_true)             },
            { CKA_SIGN,      &ck_true,  sizeof(ck_true)             },
            { CKA_VERIFY,    &ck_true,  sizeof(ck_true)             },
            { CKA_VALUE_LEN, &kLen,     sizeof(kLen)                },
            { CKA_LABEL,     (CK_VOID_PTR)kLabel, sizeof(kLabel)-1 },
            { CKA_ID,        (CK_VOID_PTR)kId,    sizeof(kId)      },
        };
        CK_MECHANISM mech = { CKM_GENERIC_SECRET_KEY_GEN, NULL_PTR, 0 };

        printf("  GenericSecret-256 (%s):\n", kLabel);
        CK_CHECK(p11->C_GenerateKey(session, &mech, tmpl,
                                    sizeof(tmpl)/sizeof(tmpl[0]), &hKey));
        printf("    hKey = %lu\n", hKey);
        DESTROY(p11, session, hKey);
    }

cleanup:
    printf("\n");
    return rc;
}
