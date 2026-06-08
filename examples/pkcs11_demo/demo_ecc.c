/*
 * demo_ecc.c — EC key pair generation + ECDSA sign/verify
 *
 * Tests P-256 (SHA-256), P-384 (SHA-384), P-521 (SHA-512) in sequence.
 * Keys are generated on the SE, signed, verified, then destroyed.
 * Key IDs: 0xEF000030 – 0xEF000032.
 */
#include "demo_common.h"

static const CK_BYTE kMsg[] = "SE051 PKCS#11 ECC sign/verify test message";

/* Per-curve test configuration */
static const struct {
    const char        *curveName;
    const CK_BYTE     *ecParams;
    CK_ULONG           ecParamsLen;
    CK_MECHANISM_TYPE  signMech;
    const char        *mechName;
    CK_ULONG           sigLen;   /* raw r||s bytes */
    const char        *label;
    CK_BYTE            id[4];
} kCurves[] = {
    {
        "P-256", kEcP256, sizeof(kEcP256),
        CKM_ECDSA_SHA256, "CKM_ECDSA_SHA256", 64,
        "sss:0xEF000030", { 0xEF,0x00,0x00,0x30 }
    },
    {
        "P-384", kEcP384, sizeof(kEcP384),
        CKM_ECDSA_SHA384, "CKM_ECDSA_SHA384", 96,
        "sss:0xEF000031", { 0xEF,0x00,0x00,0x31 }
    },
    {
        "P-521", kEcP521, sizeof(kEcP521),
        CKM_ECDSA_SHA512, "CKM_ECDSA_SHA512", 132,
        "sss:0xEF000032", { 0xEF,0x00,0x00,0x32 }
    },
};

int run_ecc(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
    int rc = 0;
    printf("--- ECC Key Gen + Sign/Verify ---\n");

    CK_BBOOL ck_true = CK_TRUE;

    for (size_t ci = 0; ci < sizeof(kCurves)/sizeof(kCurves[0]); ci++) {
        CK_OBJECT_HANDLE hPub  = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE hPriv = CK_INVALID_HANDLE;
        CK_BYTE sig[132];
        CK_ULONG sigLen = sizeof(sig);

        printf("  [%s / %s]\n", kCurves[ci].curveName, kCurves[ci].mechName);

        /* Generate key pair */
        CK_ATTRIBUTE pubTmpl[] = {
            { CKA_TOKEN,     &ck_true,                                   sizeof(ck_true)              },
            { CKA_VERIFY,    &ck_true,                                   sizeof(ck_true)              },
            { CKA_EC_PARAMS, (CK_VOID_PTR)kCurves[ci].ecParams,         kCurves[ci].ecParamsLen      },
            { CKA_LABEL,     (CK_VOID_PTR)kCurves[ci].label,            strlen(kCurves[ci].label)    },
            { CKA_ID,        (CK_VOID_PTR)kCurves[ci].id,               sizeof(kCurves[ci].id)       },
        };
        CK_ATTRIBUTE privTmpl[] = {
            { CKA_TOKEN,     &ck_true,                                   sizeof(ck_true)              },
            { CKA_SIGN,      &ck_true,                                   sizeof(ck_true)              },
            { CKA_LABEL,     (CK_VOID_PTR)kCurves[ci].label,            strlen(kCurves[ci].label)    },
            { CKA_ID,        (CK_VOID_PTR)kCurves[ci].id,               sizeof(kCurves[ci].id)       },
        };
        CK_MECHANISM mechKG = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };

        CK_RV rvkg = p11->C_GenerateKeyPair(
            session, &mechKG,
            pubTmpl,  sizeof(pubTmpl)  / sizeof(pubTmpl[0]),
            privTmpl, sizeof(privTmpl) / sizeof(privTmpl[0]),
            &hPub, &hPriv);
        if (rvkg != CKR_OK) {
            printf("    [SKIP] C_GenerateKeyPair: 0x%08lX\n", rvkg);
            continue;
        }
        printf("    C_GenerateKeyPair: hPub=%lu hPriv=%lu\n", hPub, hPriv);

        /* Export and print EC public key point */
        CK_BYTE ecPoint[200];
        CK_ATTRIBUTE ecPointAttr = { CKA_EC_POINT, ecPoint, sizeof(ecPoint) };
        if (p11->C_GetAttributeValue(session, hPub, &ecPointAttr, 1) == CKR_OK)
            print_hex("    EC point", ecPoint, ecPointAttr.ulValueLen);

        /* Sign */
        CK_MECHANISM mechSign = { kCurves[ci].signMech, NULL_PTR, 0 };
        CK_RV rvs = p11->C_SignInit(session, &mechSign, hPriv);
        if (rvs != CKR_OK) {
            printf("    [SKIP] C_SignInit: 0x%08lX\n", rvs);
            goto next;
        }
        rvs = p11->C_Sign(session,
                          (CK_BYTE_PTR)kMsg, (CK_ULONG)(sizeof(kMsg) - 1),
                          sig, &sigLen);
        if (rvs != CKR_OK) {
            printf("    [FAIL] C_Sign: 0x%08lX\n", rvs);
            rc = 1;
            goto next;
        }
        print_hex("    Signature r||s", sig, sigLen);

        /* Verify */
        CK_RV rvv = p11->C_VerifyInit(session, &mechSign, hPub);
        if (rvv == CKR_OK)
            rvv = p11->C_Verify(session,
                                (CK_BYTE_PTR)kMsg, (CK_ULONG)(sizeof(kMsg) - 1),
                                sig, sigLen);
        if (rvv != CKR_OK) {
            printf("    [FAIL] Verify: 0x%08lX\n", rvv);
            rc = 1;
            goto next;
        }
        printf("    Signature: VALID\n");

next:
        DESTROY(p11, session, hPriv);
        DESTROY(p11, session, hPub);
    }

    /* Unreachable goto label (required by CK_CHECK) */
    goto cleanup;
cleanup:
    printf("\n");
    return rc;
}
