/*
 * demo_rsa.c — RSA-2048 key pair generation, PKCS#1 v1.5 sign/verify,
 *              and PSS sign/verify.
 *
 * Key ID: 0xEF000040.
 */
#include "demo_common.h"

static const CK_BYTE kMsg[] = "SE051 PKCS#11 RSA sign/verify test message";

int run_rsa(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
    int rc = 0;
    printf("--- RSA-2048 Key Gen + Sign/Verify ---\n");

    CK_BBOOL   ck_true  = CK_TRUE;
    CK_BBOOL   ck_false = CK_FALSE;
    CK_ULONG   modBits  = 2048;
    static const char   kLabel[] = "sss:0xEF000040";
    static const CK_BYTE kId[]   = { 0xEF,0x00,0x00,0x40 };

    CK_OBJECT_HANDLE hPub  = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hPriv = CK_INVALID_HANDLE;
    CK_BYTE sig[256];
    CK_ULONG sigLen = sizeof(sig);

    /* ------------------------------------------------------------------ */
    /* Key pair generation (RSA-2048, e=65537)                              */
    /* ------------------------------------------------------------------ */
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_TOKEN,           &ck_true,             sizeof(ck_true)       },
        { CKA_VERIFY,          &ck_true,             sizeof(ck_true)       },
        { CKA_ENCRYPT,         &ck_false,            sizeof(ck_false)      },
        { CKA_MODULUS_BITS,    &modBits,             sizeof(modBits)       },
        { CKA_PUBLIC_EXPONENT, (CK_VOID_PTR)kRsaE,  sizeof(kRsaE)         },
        { CKA_LABEL,           (CK_VOID_PTR)kLabel,  sizeof(kLabel)-1      },
        { CKA_ID,              (CK_VOID_PTR)kId,     sizeof(kId)           },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN,     &ck_true,              sizeof(ck_true)           },
        { CKA_SIGN,      &ck_true,              sizeof(ck_true)           },
        { CKA_DECRYPT,   &ck_false,             sizeof(ck_false)          },
        { CKA_LABEL,     (CK_VOID_PTR)kLabel,   sizeof(kLabel)-1          },
        { CKA_ID,        (CK_VOID_PTR)kId,      sizeof(kId)               },
    };
    CK_MECHANISM mechKG = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };

    printf("  RSA-2048 keygen (slow, ~2-4 s on SE051)...\n");
    CK_CHECK(p11->C_GenerateKeyPair(
        session, &mechKG,
        pubTmpl,  sizeof(pubTmpl)  / sizeof(pubTmpl[0]),
        privTmpl, sizeof(privTmpl) / sizeof(privTmpl[0]),
        &hPub, &hPriv));
    printf("  hPub=%lu  hPriv=%lu\n", hPub, hPriv);

    /* Export public key modulus */
    CK_BYTE modBuf[256];
    CK_ATTRIBUTE modAttr = { CKA_MODULUS, modBuf, sizeof(modBuf) };
    if (p11->C_GetAttributeValue(session, hPub, &modAttr, 1) == CKR_OK)
        print_hex("  Modulus", modBuf, modAttr.ulValueLen);

    /* ------------------------------------------------------------------ */
    /* PKCS#1 v1.5 SHA-256 sign + verify                                    */
    /* ------------------------------------------------------------------ */
    printf("  [SHA-256 / CKM_SHA256_RSA_PKCS]\n");
    CK_MECHANISM mechPkcs = { CKM_SHA256_RSA_PKCS, NULL_PTR, 0 };

    sigLen = sizeof(sig);
    CK_CHECK(p11->C_SignInit(session, &mechPkcs, hPriv));
    CK_CHECK(p11->C_Sign(session,
                         (CK_BYTE_PTR)kMsg, (CK_ULONG)(sizeof(kMsg)-1),
                         sig, &sigLen));
    print_hex("  PKCS#1 signature", sig, sigLen);

    CK_CHECK(p11->C_VerifyInit(session, &mechPkcs, hPub));
    CK_CHECK(p11->C_Verify(session,
                           (CK_BYTE_PTR)kMsg, (CK_ULONG)(sizeof(kMsg)-1),
                           sig, sigLen));
    printf("  PKCS#1 signature: VALID\n");

    /* ------------------------------------------------------------------ */
    /* PSS SHA-256 sign + verify                                            */
    /* ------------------------------------------------------------------ */
    printf("  [SHA-256 / CKM_SHA256_RSA_PKCS_PSS]\n");
    CK_RSA_PKCS_PSS_PARAMS pssParams = {
        CKM_SHA256,       /* hashAlg */
        CKG_MGF1_SHA256,  /* mgf */
        32                /* sLen = hash output size */
    };
    CK_MECHANISM mechPss = { CKM_SHA256_RSA_PKCS_PSS, &pssParams, sizeof(pssParams) };

    sigLen = sizeof(sig);
    CK_RV rvs = p11->C_SignInit(session, &mechPss, hPriv);
    if (rvs != CKR_OK) {
        printf("  [SKIP] PSS not supported: 0x%08lX\n", rvs);
        goto cleanup;
    }
    rvs = p11->C_Sign(session,
                      (CK_BYTE_PTR)kMsg, (CK_ULONG)(sizeof(kMsg)-1),
                      sig, &sigLen);
    if (rvs != CKR_OK) { printf("  [FAIL] C_Sign PSS: 0x%08lX\n", rvs); rc = 1; goto cleanup; }
    print_hex("  PSS signature", sig, sigLen);

    rvs = p11->C_VerifyInit(session, &mechPss, hPub);
    if (rvs == CKR_OK)
        rvs = p11->C_Verify(session,
                            (CK_BYTE_PTR)kMsg, (CK_ULONG)(sizeof(kMsg)-1),
                            sig, sigLen);
    if (rvs != CKR_OK) { printf("  [FAIL] PSS verify: 0x%08lX\n", rvs); rc = 1; goto cleanup; }
    printf("  PSS signature: VALID\n");

cleanup:
    DESTROY(p11, session, hPriv);
    DESTROY(p11, session, hPub);
    printf("\n");
    return rc;
}
