/*
 * demo_import_object.c — C_CreateObject for AES, generic secret, and EC public key.
 *
 * The EC P-256 test key below is a well-known RFC 6979 test vector and is safe for demo
 * purposes only — never use hardcoded keys in production.
 */
#include "demo_common.h"

int run_import_object(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
    int rc = 0;
    printf("--- Import Object (C_CreateObject) ---\n");

    CK_BBOOL ck_true  = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;

    /* ------------------------------------------------------------------ */
    /* 1. Import a 16-byte AES key                                          */
    /* ------------------------------------------------------------------ */
    {
        static const CK_BYTE kAesKey[16] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        };
        static const char  kLabel[] = "sss:0xEF000082";
        static const CK_BYTE kId[]  = { 0xEF,0x00,0x00,0x82 };
        CK_OBJECT_CLASS cls    = CKO_SECRET_KEY;
        CK_KEY_TYPE     ktype  = CKK_AES;

        CK_ATTRIBUTE tmpl[] = {
            { CKA_CLASS,     &cls,                   sizeof(cls)              },
            { CKA_KEY_TYPE,  &ktype,                 sizeof(ktype)            },
            { CKA_TOKEN,     &ck_true,               sizeof(ck_true)          },
            { CKA_ENCRYPT,   &ck_true,               sizeof(ck_true)          },
            { CKA_DECRYPT,   &ck_true,               sizeof(ck_true)          },
            { CKA_SENSITIVE, &ck_false,              sizeof(ck_false)         },
            { CKA_VALUE,     (CK_VOID_PTR)kAesKey,  sizeof(kAesKey)          },
            { CKA_LABEL,     (CK_VOID_PTR)kLabel,   sizeof(kLabel)-1         },
            { CKA_ID,        (CK_VOID_PTR)kId,       sizeof(kId)             },
        };
        CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
        printf("  AES-128 import (%s):\n", kLabel);
        CK_CHECK(p11->C_CreateObject(session, tmpl, sizeof(tmpl)/sizeof(tmpl[0]), &hKey));
        printf("    hKey = %lu\n", hKey);
        DESTROY(p11, session, hKey);
    }

    /* ------------------------------------------------------------------ */
    /* 2. Import a 32-byte generic secret key (HMAC key material)          */
    /* ------------------------------------------------------------------ */
    {
        static const CK_BYTE kSecretKey[32] = {
            0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
            0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
            0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,
            0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        };
        static const char   kLabel[] = "sss:0xEF000083";
        static const CK_BYTE kId[]   = { 0xEF,0x00,0x00,0x83 };
        CK_OBJECT_CLASS cls   = CKO_SECRET_KEY;
        CK_KEY_TYPE     ktype = CKK_GENERIC_SECRET;

        CK_ATTRIBUTE tmpl[] = {
            { CKA_CLASS,     &cls,                      sizeof(cls)           },
            { CKA_KEY_TYPE,  &ktype,                    sizeof(ktype)         },
            { CKA_TOKEN,     &ck_true,                  sizeof(ck_true)       },
            { CKA_SIGN,      &ck_true,                  sizeof(ck_true)       },
            { CKA_VERIFY,    &ck_true,                  sizeof(ck_true)       },
            { CKA_SENSITIVE, &ck_false,                 sizeof(ck_false)      },
            { CKA_VALUE,     (CK_VOID_PTR)kSecretKey,  sizeof(kSecretKey)    },
            { CKA_LABEL,     (CK_VOID_PTR)kLabel,       sizeof(kLabel)-1     },
            { CKA_ID,        (CK_VOID_PTR)kId,          sizeof(kId)          },
        };
        CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
        printf("  GenericSecret-256 (%s):\n", kLabel);
        CK_CHECK(p11->C_CreateObject(session, tmpl, sizeof(tmpl)/sizeof(tmpl[0]), &hKey));
        printf("    hKey = %lu\n", hKey);
        DESTROY(p11, session, hKey);
    }

    /* ------------------------------------------------------------------ */
    /* 3. Import an EC P-256 public key                                     */
    /* The DER EC_POINT is the standard 04||X||Y uncompressed encoding      */
    /* wrapped in an ASN.1 OCTET STRING as required by PKCS#11 CKA_EC_POINT */
    /* ------------------------------------------------------------------ */
    {
        /*
         * P-256 test public key (uncompressed, DER OCTET STRING wrapping):
         *   OCTET STRING (65 bytes): 04 || X(32) || Y(32)
         */
        static const CK_BYTE kEcPoint[] = {
            /* OCTET STRING tag + length */
            0x04, 0x41,
            /* 04 = uncompressed */
            0x04,
            /* X */
            0x60,0xFE,0xD4,0xBA,0x25,0x5A,0x9D,0x31,
            0xC9,0x61,0xEB,0x74,0xC6,0x35,0x6D,0x68,
            0xC0,0x49,0xB8,0x92,0x3B,0x61,0xFA,0x6C,
            0xE6,0x69,0x62,0x2E,0x60,0xF2,0x9F,0xB6,
            /* Y */
            0x79,0x03,0xFE,0x10,0x08,0xB8,0xBC,0x99,
            0xA4,0x1A,0xE9,0xE9,0x56,0x28,0xBC,0x64,
            0xF2,0xF1,0xB2,0x0C,0x2D,0x7E,0x9F,0x51,
            0x77,0xA3,0xC2,0x94,0xD4,0x46,0x22,0x99,
        };
        static const char   kLabel[] = "sss:0xEF000080";
        static const CK_BYTE kId[]   = { 0xEF,0x00,0x00,0x80 };
        CK_OBJECT_CLASS cls   = CKO_PUBLIC_KEY;
        CK_KEY_TYPE     ktype = CKK_EC;

        CK_ATTRIBUTE tmpl[] = {
            { CKA_CLASS,     &cls,                     sizeof(cls)            },
            { CKA_KEY_TYPE,  &ktype,                   sizeof(ktype)          },
            { CKA_TOKEN,     &ck_true,                 sizeof(ck_true)        },
            { CKA_VERIFY,    &ck_true,                 sizeof(ck_true)        },
            { CKA_EC_PARAMS, (CK_VOID_PTR)kEcP256,    sizeof(kEcP256)        },
            { CKA_EC_POINT,  (CK_VOID_PTR)kEcPoint,   sizeof(kEcPoint)       },
            { CKA_LABEL,     (CK_VOID_PTR)kLabel,      sizeof(kLabel)-1      },
            { CKA_ID,        (CK_VOID_PTR)kId,         sizeof(kId)           },
        };
        CK_OBJECT_HANDLE hPub = CK_INVALID_HANDLE;
        printf("  EC P-256 public key import (%s):\n", kLabel);
        CK_CHECK(p11->C_CreateObject(session, tmpl, sizeof(tmpl)/sizeof(tmpl[0]), &hPub));
        printf("    hPub = %lu\n", hPub);

        /* Read back the EC params */
        CK_BYTE ecParamsBuf[16];
        CK_ATTRIBUTE readback = { CKA_EC_PARAMS, ecParamsBuf, sizeof(ecParamsBuf) };
        if (p11->C_GetAttributeValue(session, hPub, &readback, 1) == CKR_OK)
            print_hex("  EC_PARAMS readback", ecParamsBuf, readback.ulValueLen);

        DESTROY(p11, session, hPub);
    }

cleanup:
    printf("\n");
    return rc;
}
