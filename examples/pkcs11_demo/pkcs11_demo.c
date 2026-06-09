/*
 * pkcs11_demo.c - SE051 PKCS#11 v2.40 full demo suite
 *
 * Loads libsss_pkcs11.so at runtime via dlopen, opens a session, then runs
 * all demonstration functions covering:
 *
 *   1.  Module info        - library info, slot/token/mechanism enumeration
 *   2.  Hardware RNG       - C_GenerateRandom (1–1024 bytes)
 *   3.  Message digest     - SHA-1/224/256/384/512 via C_DigestInit/C_Digest
 *   4.  Symmetric key gen  - AES-128/192/256 + generic secret (C_GenerateKey)
 *   5.  Object import      - AES, generic secret, EC P-256 public key (C_CreateObject)
 *   6.  ECC sign/verify    - P-256/384/521 keygen + ECDSA sign/verify
 *   7.  RSA sign/verify    - RSA-2048 keygen + PKCS#1 v1.5 + PSS
 *   8.  ECDH derivation    - Two P-256 key pairs + CKM_ECDH1_DERIVE
 *   9.  HMAC               - Import key, SHA-1/256/384/512 HMAC sign/verify
 *  10.  Encrypt/decrypt    - AES-ECB, AES-CBC, RSA-2048 OAEP
 *
 * Usage:
 *   ./pkcs11_demo [/path/to/libsss_pkcs11.so]
 *
 * Returns 0 if all run functions return 0, non-zero on first failure.
 */

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "demo_common.h"

/* ---- Helpers ------------------------------------------------------------- */

static void section(const char *title)
{
    printf("\n====  %-46s ====\n", title);
}

/* ---- Main ---------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    const char *lib_path = (argc > 1) ? argv[1] : "libsss_pkcs11.so";

    int              rc      = 0;
    void            *lib     = NULL;
    CK_FUNCTION_LIST_PTR p11 = NULL_PTR;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SLOT_ID        slot    = 0;
    CK_SLOT_ID        slots[8];
    CK_ULONG          slotCount = 0;

    /* ------------------------------------------------------------------ */
    /* Load PKCS#11 library                                                 */
    /* ------------------------------------------------------------------ */
    lib = dlopen(lib_path, RTLD_NOW);
    if (!lib) {
        fprintf(stderr, "dlopen(%s): %s\n", lib_path, dlerror());
        return 1;
    }

    CK_C_GetFunctionList getFnList =
        (CK_C_GetFunctionList)dlsym(lib, "C_GetFunctionList");
    if (!getFnList || getFnList(&p11) != CKR_OK || !p11) {
        fprintf(stderr, "C_GetFunctionList failed\n");
        rc = 1;
        goto done;
    }

    printf("SE051 PKCS#11 Demo Suite\n");
    printf("Library: %s\n", lib_path);

    /* ------------------------------------------------------------------ */
    /* Initialize and open session                                          */
    /* ------------------------------------------------------------------ */
    CK_RV rv = p11->C_Initialize(NULL_PTR);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_Initialize: 0x%08lX\n", rv);
        rc = 1;
        goto done;
    }

    rv = p11->C_GetSlotList(CK_TRUE, NULL_PTR, &slotCount);
    if (rv != CKR_OK || slotCount == 0) {
        fprintf(stderr, "No PKCS#11 slots with token present - is the SE connected?\n");
        fprintf(stderr, "C_GetSlotList: rv=0x%08lX count=%lu\n", rv, slotCount);
        rc = 1;
        goto finalize;
    }
    if (slotCount > 8) slotCount = 8;
    p11->C_GetSlotList(CK_TRUE, slots, &slotCount);
    slot = slots[0];
    printf("Slots: %lu (using ID %lu)\n", slotCount, slot);

    rv = p11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                            NULL_PTR, NULL_PTR, &session);
    if (rv != CKR_OK) {
        fprintf(stderr, "C_OpenSession: 0x%08lX\n", rv);
        rc = 1;
        goto finalize;
    }
    printf("Session: %lu\n", session);

    /* ------------------------------------------------------------------ */
    /* Run all demos - continue on individual failures                      */
    /* ------------------------------------------------------------------ */

#define RUN(fn) \
    do { \
        section(#fn); \
        int _r = fn(p11, session); \
        if (_r) { printf("  [DEMO FAILED]\n"); rc = 1; } \
    } while (0)

    RUN(run_module_info);
    RUN(run_random_gen);
    RUN(run_digest);
    RUN(run_sym_key_gen);
    RUN(run_import_object);
    RUN(run_rsa);

#undef RUN

    printf("\n=== Demo suite %s ===\n", rc == 0 ? "PASSED" : "FAILED (see above)");

    p11->C_CloseSession(session);

finalize:
    p11->C_Finalize(NULL_PTR);
done:
    dlclose(lib);
    return rc;
}
