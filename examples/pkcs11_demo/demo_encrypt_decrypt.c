/*
 * demo_encrypt_decrypt.c
 *   - AES-128 ECB encrypt/decrypt
 *   - AES-128 CBC encrypt/decrypt
 *   - RSA-2048 OAEP encrypt/decrypt
 *
 * AES key ID: 0xEF000050, RSA key ID: 0xEF000051
 */
#include "demo_common.h"
#include <string.h>

static const CK_BYTE kPlain[32] = {
    'S','E','0','5','1',' ','P','K','C','S','#','1','1',' ',
    'e','n','c','r','y','p','t',' ','d','e','m','o','!','!','!','!','!','!'
};

/* AES requires plaintext to be a multiple of 16 bytes */
static const CK_BYTE kPlain16[16] = {
    'S','E','0','5','1',' ','A','E','S',' ','t','e','s','t','!','!'
};

int run_encrypt_decrypt(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
    int rc = 0;
    printf("--- Encrypt / Decrypt ---\n");

    CK_BBOOL ck_true  = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;

    /* ------------------------------------------------------------------ */
    /* AES-128 key generation                                               */
    /* ------------------------------------------------------------------ */
    CK_OBJECT_HANDLE hAes = CK_INVALID_HANDLE;
    {
        static const char   kLabel[] = "sss:0xEF000050";
        static const CK_BYTE kId[]   = { 0xEF,0x00,0x00,0x50 };
        CK_ULONG kLen = 16;

        CK_ATTRIBUTE tmpl[] = {
            { CKA_TOKEN,     &ck_true,              sizeof(ck_true)       },
            { CKA_ENCRYPT,   &ck_true,              sizeof(ck_true)       },
            { CKA_DECRYPT,   &ck_true,              sizeof(ck_true)       },
            { CKA_SENSITIVE, &ck_false,             sizeof(ck_false)      },
            { CKA_VALUE_LEN, &kLen,                 sizeof(kLen)          },
            { CKA_LABEL,     (CK_VOID_PTR)kLabel,   sizeof(kLabel)-1      },
            { CKA_ID,        (CK_VOID_PTR)kId,      sizeof(kId)           },
        };
        CK_MECHANISM mech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
        CK_CHECK(p11->C_GenerateKey(session, &mech, tmpl,
                                    sizeof(tmpl)/sizeof(tmpl[0]), &hAes));
        printf("  AES-128 key generated: hAes=%lu\n", hAes);
    }

    CK_BYTE ct[64], pt2[64];
    CK_ULONG ctLen, pt2Len;

    /* ------------------------------------------------------------------ */
    /* AES-ECB encrypt + decrypt                                            */
    /* ------------------------------------------------------------------ */
    printf("  [AES-ECB]\n");
    {
        CK_MECHANISM mechEcb = { CKM_AES_ECB, NULL_PTR, 0 };

        ctLen = sizeof(ct);
        CK_CHECK(p11->C_EncryptInit(session, &mechEcb, hAes));
        CK_CHECK(p11->C_Encrypt(session,
                                (CK_BYTE_PTR)kPlain16, sizeof(kPlain16),
                                ct, &ctLen));
        print_hex("  CT", ct, ctLen);

        pt2Len = sizeof(pt2);
        CK_CHECK(p11->C_DecryptInit(session, &mechEcb, hAes));
        CK_CHECK(p11->C_Decrypt(session, ct, ctLen, pt2, &pt2Len));
        if (pt2Len == sizeof(kPlain16) && memcmp(pt2, kPlain16, pt2Len) == 0)
            printf("  AES-ECB roundtrip: OK\n");
        else {
            printf("  [FAIL] AES-ECB roundtrip mismatch\n");
            rc = 1;
            goto cleanup;
        }
    }

    /* ------------------------------------------------------------------ */
    /* AES-CBC encrypt + decrypt (IV = all zeros)                           */
    /* ------------------------------------------------------------------ */
    printf("  [AES-CBC]\n");
    {
        CK_BYTE iv[16] = { 0 };
        CK_MECHANISM mechCbc = { CKM_AES_CBC, iv, sizeof(iv) };

        ctLen = sizeof(ct);
        CK_CHECK(p11->C_EncryptInit(session, &mechCbc, hAes));
        CK_CHECK(p11->C_Encrypt(session,
                                (CK_BYTE_PTR)kPlain16, sizeof(kPlain16),
                                ct, &ctLen));
        print_hex("  CT", ct, ctLen);

        /* Reset IV for decryption */
        memset(iv, 0, sizeof(iv));
        pt2Len = sizeof(pt2);
        CK_CHECK(p11->C_DecryptInit(session, &mechCbc, hAes));
        CK_CHECK(p11->C_Decrypt(session, ct, ctLen, pt2, &pt2Len));
        if (pt2Len == sizeof(kPlain16) && memcmp(pt2, kPlain16, pt2Len) == 0)
            printf("  AES-CBC roundtrip: OK\n");
        else {
            printf("  [FAIL] AES-CBC roundtrip mismatch\n");
            rc = 1;
            goto cleanup;
        }
    }
    DESTROY(p11, session, hAes);

    /* ------------------------------------------------------------------ */
    /* RSA-2048 OAEP encrypt + decrypt                                      */
    /* ------------------------------------------------------------------ */
    printf("  [RSA-OAEP]\n");
    {
        CK_OBJECT_HANDLE hRsaPub  = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE hRsaPriv = CK_INVALID_HANDLE;
        static const char   kLabel[] = "sss:0xEF000051";
        static const CK_BYTE kId[]   = { 0xEF,0x00,0x00,0x51 };
        CK_ULONG modBits = 2048;

        CK_ATTRIBUTE pubTmpl[] = {
            { CKA_TOKEN,           &ck_true,              sizeof(ck_true)   },
            { CKA_ENCRYPT,         &ck_true,              sizeof(ck_true)   },
            { CKA_MODULUS_BITS,    &modBits,              sizeof(modBits)   },
            { CKA_PUBLIC_EXPONENT, (CK_VOID_PTR)kRsaE,   sizeof(kRsaE)     },
            { CKA_LABEL,           (CK_VOID_PTR)kLabel,   sizeof(kLabel)-1  },
            { CKA_ID,              (CK_VOID_PTR)kId,      sizeof(kId)       },
        };
        CK_ATTRIBUTE privTmpl[] = {
            { CKA_TOKEN,   &ck_true,              sizeof(ck_true)           },
            { CKA_DECRYPT, &ck_true,              sizeof(ck_true)           },
            { CKA_LABEL,   (CK_VOID_PTR)kLabel,   sizeof(kLabel)-1          },
            { CKA_ID,      (CK_VOID_PTR)kId,      sizeof(kId)               },
        };
        CK_MECHANISM mechKG = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };

        printf("  RSA-2048 keygen (slow)...\n");
        CK_RV rvkg = p11->C_GenerateKeyPair(
            session, &mechKG,
            pubTmpl,  sizeof(pubTmpl)  / sizeof(pubTmpl[0]),
            privTmpl, sizeof(privTmpl) / sizeof(privTmpl[0]),
            &hRsaPub, &hRsaPriv);
        if (rvkg != CKR_OK) {
            printf("  [SKIP] RSA keygen: 0x%08lX\n", rvkg);
            goto cleanup;
        }
        printf("  hRsaPub=%lu hRsaPriv=%lu\n", hRsaPub, hRsaPriv);

        CK_RSA_PKCS_OAEP_PARAMS oaep = {
            CKM_SHA256,           /* hashAlg */
            CKG_MGF1_SHA256,      /* mgf */
            CKZ_DATA_SPECIFIED,   /* source */
            NULL_PTR, 0           /* pSourceData, ulSourceDataLen */
        };
        CK_MECHANISM mechOaep = { CKM_RSA_PKCS_OAEP, &oaep, sizeof(oaep) };

        CK_BYTE rsaCt[256];
        CK_ULONG rsaCtLen = sizeof(rsaCt);
        CK_RV rve = p11->C_EncryptInit(session, &mechOaep, hRsaPub);
        if (rve != CKR_OK) {
            printf("  [SKIP] RSA OAEP EncryptInit: 0x%08lX\n", rve);
        } else {
            rve = p11->C_Encrypt(session,
                                 (CK_BYTE_PTR)kPlain, sizeof(kPlain),
                                 rsaCt, &rsaCtLen);
            if (rve != CKR_OK) {
                printf("  [FAIL] RSA OAEP Encrypt: 0x%08lX\n", rve);
                rc = 1;
            } else {
                print_hex("  RSA-OAEP CT", rsaCt, rsaCtLen);

                CK_BYTE rsaPt[256];
                CK_ULONG rsaPtLen = sizeof(rsaPt);
                rve = p11->C_DecryptInit(session, &mechOaep, hRsaPriv);
                if (rve == CKR_OK)
                    rve = p11->C_Decrypt(session, rsaCt, rsaCtLen, rsaPt, &rsaPtLen);
                if (rve != CKR_OK) {
                    printf("  [FAIL] RSA OAEP Decrypt: 0x%08lX\n", rve);
                    rc = 1;
                } else if (rsaPtLen == sizeof(kPlain) &&
                           memcmp(rsaPt, kPlain, sizeof(kPlain)) == 0) {
                    printf("  RSA-OAEP roundtrip: OK\n");
                } else {
                    printf("  [FAIL] RSA-OAEP plaintext mismatch\n");
                    rc = 1;
                }
            }
        }
        DESTROY(p11, session, hRsaPriv);
        DESTROY(p11, session, hRsaPub);
    }

cleanup:
    DESTROY(p11, session, hAes);
    printf("\n");
    return rc;
}
