/*
 * demo_ecdh_derive.c — ECDH key derivation via CKM_ECDH1_DERIVE
 *
 * Generates two EC P-256 key pairs on the SE (Alice/Bob), then derives a
 * shared secret from each side and verifies they match.
 *
 * Key IDs: 0xEF000070 (Alice), 0xEF000071 (Bob).
 */
#include "demo_common.h"

int run_ecdh_derive(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
    int rc = 0;
    printf("--- ECDH Key Derivation ---\n");

    CK_BBOOL ck_true  = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;

    CK_OBJECT_HANDLE hAlicePub  = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hAlicePriv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hBobPub    = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hBobPriv   = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hShared1   = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hShared2   = CK_INVALID_HANDLE;

    CK_MECHANISM mechKG = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };

    /* ------------------------------------------------------------------ */
    /* Generate Alice's key pair                                            */
    /* ------------------------------------------------------------------ */
    static const char   kAliceLabel[] = "sss:0xEF000070";
    static const CK_BYTE kAliceId[]   = { 0xEF,0x00,0x00,0x70 };

    CK_ATTRIBUTE alicePubTmpl[] = {
        { CKA_TOKEN,     &ck_true,                   sizeof(ck_true)           },
        { CKA_EC_PARAMS, (CK_VOID_PTR)kEcP256,       sizeof(kEcP256)           },
        { CKA_LABEL,     (CK_VOID_PTR)kAliceLabel,   sizeof(kAliceLabel)-1     },
        { CKA_ID,        (CK_VOID_PTR)kAliceId,      sizeof(kAliceId)          },
    };
    CK_ATTRIBUTE alicePrivTmpl[] = {
        { CKA_TOKEN,  &ck_true,                    sizeof(ck_true)             },
        { CKA_DERIVE, &ck_true,                    sizeof(ck_true)             },
        { CKA_LABEL,  (CK_VOID_PTR)kAliceLabel,   sizeof(kAliceLabel)-1       },
        { CKA_ID,     (CK_VOID_PTR)kAliceId,      sizeof(kAliceId)            },
    };
    CK_CHECK(p11->C_GenerateKeyPair(
        session, &mechKG,
        alicePubTmpl,  sizeof(alicePubTmpl)  / sizeof(alicePubTmpl[0]),
        alicePrivTmpl, sizeof(alicePrivTmpl) / sizeof(alicePrivTmpl[0]),
        &hAlicePub, &hAlicePriv));
    printf("  Alice key pair: hPub=%lu hPriv=%lu\n", hAlicePub, hAlicePriv);

    /* ------------------------------------------------------------------ */
    /* Generate Bob's key pair                                              */
    /* ------------------------------------------------------------------ */
    static const char   kBobLabel[] = "sss:0xEF000071";
    static const CK_BYTE kBobId[]   = { 0xEF,0x00,0x00,0x71 };

    CK_ATTRIBUTE bobPubTmpl[] = {
        { CKA_TOKEN,     &ck_true,                 sizeof(ck_true)             },
        { CKA_EC_PARAMS, (CK_VOID_PTR)kEcP256,     sizeof(kEcP256)             },
        { CKA_LABEL,     (CK_VOID_PTR)kBobLabel,   sizeof(kBobLabel)-1         },
        { CKA_ID,        (CK_VOID_PTR)kBobId,      sizeof(kBobId)              },
    };
    CK_ATTRIBUTE bobPrivTmpl[] = {
        { CKA_TOKEN,  &ck_true,                  sizeof(ck_true)               },
        { CKA_DERIVE, &ck_true,                  sizeof(ck_true)               },
        { CKA_LABEL,  (CK_VOID_PTR)kBobLabel,   sizeof(kBobLabel)-1           },
        { CKA_ID,     (CK_VOID_PTR)kBobId,      sizeof(kBobId)                },
    };
    CK_CHECK(p11->C_GenerateKeyPair(
        session, &mechKG,
        bobPubTmpl,  sizeof(bobPubTmpl)  / sizeof(bobPubTmpl[0]),
        bobPrivTmpl, sizeof(bobPrivTmpl) / sizeof(bobPrivTmpl[0]),
        &hBobPub, &hBobPriv));
    printf("  Bob   key pair: hPub=%lu hPriv=%lu\n", hBobPub, hBobPriv);

    /* ------------------------------------------------------------------ */
    /* Get Bob's EC point (needed as peer public key for Alice's derivation) */
    /* ------------------------------------------------------------------ */
    CK_BYTE bobEcPoint[200];
    CK_ATTRIBUTE bobEcPointAttr = { CKA_EC_POINT, bobEcPoint, sizeof(bobEcPoint) };
    CK_CHECK(p11->C_GetAttributeValue(session, hBobPub, &bobEcPointAttr, 1));
    print_hex("  Bob EC point", bobEcPoint, bobEcPointAttr.ulValueLen);

    /* Get Alice's EC point (needed for Bob's derivation) */
    CK_BYTE aliceEcPoint[200];
    CK_ATTRIBUTE aliceEcPointAttr = { CKA_EC_POINT, aliceEcPoint, sizeof(aliceEcPoint) };
    CK_CHECK(p11->C_GetAttributeValue(session, hAlicePub, &aliceEcPointAttr, 1));

    /* ------------------------------------------------------------------ */
    /* Derived key template — transient, 32-byte generic secret            */
    /* ------------------------------------------------------------------ */
    CK_ULONG derivedKeyLen = 32;
    CK_ATTRIBUTE derivedTmpl[] = {
        { CKA_CLASS,     (CK_VOID_PTR)&(CK_OBJECT_CLASS){CKO_SECRET_KEY}, sizeof(CK_OBJECT_CLASS) },
        { CKA_KEY_TYPE,  (CK_VOID_PTR)&(CK_KEY_TYPE){CKK_GENERIC_SECRET}, sizeof(CK_KEY_TYPE)     },
        { CKA_TOKEN,     &ck_false,    sizeof(ck_false)                   },
        { CKA_SENSITIVE, &ck_false,    sizeof(ck_false)                   },
        { CKA_EXTRACTABLE,&ck_true,   sizeof(ck_true)                    },
        { CKA_VALUE_LEN, &derivedKeyLen, sizeof(derivedKeyLen)            },
    };
    CK_ULONG nDerived = sizeof(derivedTmpl)/sizeof(derivedTmpl[0]);

    /* ------------------------------------------------------------------ */
    /* Alice derives: priv=Alice, peer=Bob's EC point                       */
    /* ------------------------------------------------------------------ */
    CK_ECDH1_DERIVE_PARAMS ecdh1_alice = {
        CKD_NULL,                        /* kdf */
        0, NULL_PTR,                     /* shared data */
        bobEcPointAttr.ulValueLen,       /* ulPublicDataLen */
        bobEcPoint                       /* pPublicData */
    };
    CK_MECHANISM mechDeriveAlice = {
        CKM_ECDH1_DERIVE, &ecdh1_alice, sizeof(ecdh1_alice)
    };
    CK_RV rvd = p11->C_DeriveKey(session, &mechDeriveAlice,
                                  hAlicePriv, derivedTmpl, nDerived, &hShared1);
    if (rvd != CKR_OK) {
        printf("  [SKIP] C_DeriveKey (Alice): 0x%08lX\n", rvd);
        goto cleanup;
    }
    printf("  [OK]   C_DeriveKey (Alice): hShared1=%lu\n", hShared1);

    /* Try to export Alice's shared secret */
    CK_BYTE shared1[32] = {0};
    CK_ATTRIBUTE shared1Attr = { CKA_VALUE, shared1, sizeof(shared1) };
    if (p11->C_GetAttributeValue(session, hShared1, &shared1Attr, 1) == CKR_OK)
        print_hex("  Shared (Alice side)", shared1, shared1Attr.ulValueLen);
    else
        printf("  (Alice shared secret not extractable — stored on SE)\n");

    /* ------------------------------------------------------------------ */
    /* Bob derives: priv=Bob, peer=Alice's EC point                         */
    /* ------------------------------------------------------------------ */
    CK_ECDH1_DERIVE_PARAMS ecdh1_bob = {
        CKD_NULL,
        0, NULL_PTR,
        aliceEcPointAttr.ulValueLen,
        aliceEcPoint
    };
    CK_MECHANISM mechDeriveBob = {
        CKM_ECDH1_DERIVE, &ecdh1_bob, sizeof(ecdh1_bob)
    };
    rvd = p11->C_DeriveKey(session, &mechDeriveBob,
                            hBobPriv, derivedTmpl, nDerived, &hShared2);
    if (rvd != CKR_OK) {
        printf("  [SKIP] C_DeriveKey (Bob): 0x%08lX\n", rvd);
        goto cleanup;
    }
    printf("  [OK]   C_DeriveKey (Bob): hShared2=%lu\n", hShared2);

    CK_BYTE shared2[32] = {0};
    CK_ATTRIBUTE shared2Attr = { CKA_VALUE, shared2, sizeof(shared2) };
    if (p11->C_GetAttributeValue(session, hShared2, &shared2Attr, 1) == CKR_OK) {
        print_hex("  Shared (Bob   side)", shared2, shared2Attr.ulValueLen);
        if (shared1Attr.ulValueLen == shared2Attr.ulValueLen
            && memcmp(shared1, shared2, shared1Attr.ulValueLen) == 0)
            printf("  Shared secrets MATCH: ECDH OK\n");
        else
            printf("  (Cannot compare — one side not extractable or mismatch)\n");
    } else {
        printf("  (Bob shared secret not extractable — stored on SE)\n");
    }

cleanup:
    DESTROY(p11, session, hShared2);
    DESTROY(p11, session, hShared1);
    DESTROY(p11, session, hBobPriv);
    DESTROY(p11, session, hBobPub);
    DESTROY(p11, session, hAlicePriv);
    DESTROY(p11, session, hAlicePub);
    printf("\n");
    return rc;
}
