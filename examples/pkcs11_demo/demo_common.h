#pragma once
/*
 * Shared types, macros and helpers for the PKCS#11 demo suite.
 * Each demo file includes this header and receives a
 *   int run_XXX(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
 * prototype.
 */
#include "cryptoki.h"
#include <stdio.h>
#include <string.h>

/* ---- EC curve OID parameters (DER ECParameters namedCurve) -------------- */
static const CK_BYTE kEcP256[] = {
    0x06,0x08, 0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07 /* 1.2.840.10045.3.1.7  */
};
static const CK_BYTE kEcP384[] = {
    0x06,0x05, 0x2B,0x81,0x04,0x00,0x22               /* 1.3.132.0.34          */
};
static const CK_BYTE kEcP521[] = {
    0x06,0x05, 0x2B,0x81,0x04,0x00,0x23               /* 1.3.132.0.35          */
};

/* ---- RSA public exponent 65537 ------------------------------------------ */
static const CK_BYTE kRsaE[] = { 0x01, 0x00, 0x01 };

/* ---- Helpers -------------------------------------------------------------- */
static inline void print_hex(const char *label, const CK_BYTE *buf, CK_ULONG len)
{
    printf("  %-26s(%3lu B): ", label, len);
    for (CK_ULONG i = 0; i < len && i < 48; i++)
        printf("%02x", buf[i]);
    if (len > 48)
        printf("...");
    printf("\n");
}

/* CK_CHECK — requires local `int rc = 0` and `cleanup:` label in caller */
#define CK_CHECK(call) \
    do { \
        CK_RV _rv = (call); \
        if (_rv != CKR_OK) { \
            printf("  [FAIL] %s: 0x%08lX\n", #call, _rv); \
            rc = 1; \
            goto cleanup; \
        } \
        printf("  [OK]   %s\n", #call); \
    } while (0)

/* Destroy a handle if non-zero, ignoring errors */
#define DESTROY(p11, session, h) \
    do { if ((h) != CK_INVALID_HANDLE) { (p11)->C_DestroyObject(session, h); (h) = CK_INVALID_HANDLE; } } while (0)

/* ---- Demo function prototypes -------------------------------------------- */
int run_module_info     (CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session);
int run_random_gen      (CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session);
int run_digest          (CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session);
int run_sym_key_gen     (CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session);
int run_import_object   (CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session);
int run_ecc             (CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session);
int run_rsa             (CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session);
int run_ecdh_derive     (CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session);
int run_hmac            (CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session);
int run_encrypt_decrypt (CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session);
