/* demo_module_info.c — C_GetInfo, slot/token info, mechanism list, object enumeration */
#include "demo_common.h"

int run_module_info(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
    int rc = 0;
    printf("--- Module Info ---\n");

    /* Library info */
    CK_INFO libInfo;
    CK_CHECK(p11->C_GetInfo(&libInfo));
    printf("  Manufacturer : %.32s\n", libInfo.manufacturerID);
    printf("  Description  : %.32s\n", libInfo.libraryDescription);
    printf("  Version      : %u.%u\n",
           libInfo.libraryVersion.major, libInfo.libraryVersion.minor);
    printf("  PKCS#11 spec : %u.%u\n",
           libInfo.cryptokiVersion.major, libInfo.cryptokiVersion.minor);

    /* All slots (including ones with no token) */
    CK_ULONG allSlotCount = 0;
    CK_CHECK(p11->C_GetSlotList(CK_FALSE, NULL_PTR, &allSlotCount));
    printf("  Slots total  : %lu\n", allSlotCount);

    /* Slots with a token present */
    CK_ULONG tokenSlotCount = 0;
    CK_CHECK(p11->C_GetSlotList(CK_TRUE, NULL_PTR, &tokenSlotCount));
    printf("  Slots w/token: %lu\n", tokenSlotCount);

    if (tokenSlotCount == 0) {
        printf("  (no token present — is the SE connected?)\n");
        goto cleanup;
    }

    CK_SLOT_ID slots[8];
    if (tokenSlotCount > 8) tokenSlotCount = 8;
    CK_CHECK(p11->C_GetSlotList(CK_TRUE, slots, &tokenSlotCount));

    for (CK_ULONG i = 0; i < tokenSlotCount; i++) {
        printf("\n  == Slot %lu (ID %lu) ==\n", i, slots[i]);

        /* Slot info */
        CK_SLOT_INFO slotInfo;
        if (p11->C_GetSlotInfo(slots[i], &slotInfo) == CKR_OK) {
            printf("    Slot desc  : %.64s\n", slotInfo.slotDescription);
            printf("    HW version : %u.%u  FW: %u.%u\n",
                   slotInfo.hardwareVersion.major, slotInfo.hardwareVersion.minor,
                   slotInfo.firmwareVersion.major, slotInfo.firmwareVersion.minor);
        }

        /* Token info */
        CK_TOKEN_INFO tokenInfo;
        if (p11->C_GetTokenInfo(slots[i], &tokenInfo) == CKR_OK) {
            printf("    Token label: %.32s\n", tokenInfo.label);
            printf("    Manufacturer:%.32s\n", tokenInfo.manufacturerID);
            printf("    Model      : %.16s\n", tokenInfo.model);
        }

        /* Mechanism list */
        CK_ULONG mechCount = 0;
        if (p11->C_GetMechanismList(slots[i], NULL_PTR, &mechCount) == CKR_OK
            && mechCount > 0)
        {
            printf("    Mechanisms : %lu\n", mechCount);
            CK_MECHANISM_TYPE mechBuf[128];
            CK_ULONG fetchCount = mechCount < 128 ? mechCount : 128;
            if (p11->C_GetMechanismList(slots[i], mechBuf, &fetchCount) == CKR_OK) {
                /* Print a few well-known ones */
                static const struct { CK_MECHANISM_TYPE id; const char *name; } kKnown[] = {
                    { CKM_RSA_PKCS_KEY_PAIR_GEN, "CKM_RSA_PKCS_KEY_PAIR_GEN" },
                    { CKM_RSA_PKCS,              "CKM_RSA_PKCS"              },
                    { CKM_SHA256_RSA_PKCS,       "CKM_SHA256_RSA_PKCS"       },
                    { CKM_SHA256_RSA_PKCS_PSS,   "CKM_SHA256_RSA_PKCS_PSS"   },
                    { CKM_RSA_PKCS_OAEP,         "CKM_RSA_PKCS_OAEP"         },
                    { CKM_EC_KEY_PAIR_GEN,        "CKM_EC_KEY_PAIR_GEN"      },
                    { CKM_ECDSA,                  "CKM_ECDSA"                },
                    { CKM_ECDSA_SHA256,           "CKM_ECDSA_SHA256"         },
                    { CKM_ECDH1_DERIVE,           "CKM_ECDH1_DERIVE"         },
                    { CKM_AES_KEY_GEN,            "CKM_AES_KEY_GEN"          },
                    { CKM_AES_ECB,                "CKM_AES_ECB"              },
                    { CKM_AES_CBC,                "CKM_AES_CBC"              },
                    { CKM_SHA256_HMAC,            "CKM_SHA256_HMAC"          },
                    { CKM_SHA256,                 "CKM_SHA256"               },
                    { CKM_GENERIC_SECRET_KEY_GEN, "CKM_GENERIC_SECRET_KEY_GEN"},
                };
                for (CK_ULONG m = 0; m < fetchCount; m++) {
                    const char *name = NULL;
                    for (size_t k = 0; k < sizeof(kKnown)/sizeof(kKnown[0]); k++)
                        if (kKnown[k].id == mechBuf[m]) { name = kKnown[k].name; break; }
                    if (name)
                        printf("      0x%08lX  %s\n", mechBuf[m], name);
                }
            }
        }
    }

    /* Object enumeration on the supplied session */
    printf("\n  == Objects in current session ==\n");
    CK_CHECK(p11->C_FindObjectsInit(session, NULL_PTR, 0));
    CK_OBJECT_HANDLE handles[64];
    CK_ULONG found = 0;
    (void)p11->C_FindObjects(session, handles, 64, &found);
    (void)p11->C_FindObjectsFinal(session);
    printf("    Objects found: %lu\n", found);
    for (CK_ULONG i = 0; i < found; i++) {
        CK_OBJECT_CLASS cls = 0;
        CK_ATTRIBUTE clsAttr = { CKA_CLASS, &cls, sizeof(cls) };
        const char *clsName = "unknown";
        if (p11->C_GetAttributeValue(session, handles[i], &clsAttr, 1) == CKR_OK) {
            switch (cls) {
                case CKO_PUBLIC_KEY:  clsName = "PUBLIC_KEY";  break;
                case CKO_PRIVATE_KEY: clsName = "PRIVATE_KEY"; break;
                case CKO_SECRET_KEY:  clsName = "SECRET_KEY";  break;
                case CKO_CERTIFICATE: clsName = "CERTIFICATE"; break;
                case CKO_DATA:        clsName = "DATA";        break;
                default:              clsName = "other";       break;
            }
        }
        printf("    handle=%lu  class=%s\n", handles[i], clsName);
    }

cleanup:
    printf("\n");
    return rc;
}
