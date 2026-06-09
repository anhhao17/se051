/**
 * @file scp03_rotate.cpp
 * @brief Platform SCP03 static-key rotation - GP PUT KEY (port of NXP demo).
 */

#include "scp03_rotate.hpp"
#include "scp03_keyfile.hpp"
#include "sw_decode.hpp"
#include "log.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>

extern "C" {
#include <ex_sss_boot.h>
#include <fsl_sss_api.h>
#include <fsl_sss_se05x_apis.h>
#include <fsl_sss_se05x_types.h>
#include <se05x_tlv.h> // tlvHeader_t, DoAPDUTxRx_s_Case4, smStatus_t, SM_OK
}

// GlobalPlatform / NXP PUT KEY constants.  These normally come from
// se05x_const.h / se05x_APDU.h, but those headers are not on this translation
// unit's include path in every plug-and-trust fork.  The values are fixed by
// the GP card spec, so define them with guards (a real definition, if visible,
// wins).  See nxScp03_Const.h: CLA_GP_7816=0x80, INS_GP_PUT_KEY=0xD8,
// GPCS_KEY_TYPE_AES=0x88, CRYPTO_KEY_CHECK_LEN=3.
#ifndef GP_CLA_BYTE
#define GP_CLA_BYTE 0x80 // GP 7816-4 CLA
#endif
#ifndef GP_INS_PUTKEY
#define GP_INS_PUTKEY 0xD8 // GP PUT KEY
#endif
#ifndef GP_P2_NEW_MULTI
// P2 for PUT KEY with multiple keys: b8=1 (multiple present), b7-b1 = new KVN.
// Computed at runtime from keyVer; do not define a single constant.
#define GP_P2_NEW_MULTI(kvn) ((uint8_t)((kvn) | 0x80u))
#endif
#ifndef PUT_KEYS_KEY_TYPE_CODING_AES
#define PUT_KEYS_KEY_TYPE_CODING_AES 0x88 // AES key type
#endif
#ifndef CRYPTO_KEY_CHECK_LEN
#define CRYPTO_KEY_CHECK_LEN 3 // KCV length
#endif

namespace se05x {

namespace {

constexpr int kScpKeyLen = 16; // 128-bit keys (ROTATE_PLATFORMSCP03_128BITLEN=1)

inline NXSCP03_StaticCtx_t *staticCtx(Session &s) {
    return s.bootCtx()->se05x_open_ctx.auth.ctx.scp03.pStatic_ctx;
}

// Load the current DEK into pStatic_ctx->Dek so genKcvAndEncryptKey can wrap
// with it.  A standard ex_sss_boot_open does NOT populate this object, so we
// replicate the demo's ex_sss_entry preamble.  The DEK is read from the SCP03
// key file ($EX_SSS_BOOT_SCP03_PATH) via the shared Scp03KeyFile parser.
void loadCurrentDek(Session &s) {
    const char *path = std::getenv("EX_SSS_BOOT_SCP03_PATH");
    if (!path || !*path)
        throw std::runtime_error(
            "rotateScp03: $EX_SSS_BOOT_SCP03_PATH is not set; cannot read the current DEK "
            "needed to wrap the new keys");

    uint8_t dek[kScpKeyLen] = {};
    if (!Scp03KeyFile::readDek(path, dek))
        throw std::runtime_error(
            std::string("rotateScp03: cannot read current DEK from '") + path +
            "' (need a 'DEK <32 hex>' line; this is the key used to wrap the new keys)");

    NXSCP03_StaticCtx_t *st = staticCtx(s);
    st->key_len = kScpKeyLen;
    check(sss_host_key_store_set_key(st->Dek.keyStore, &st->Dek, dek, kScpKeyLen, kScpKeyLen * 8,
                                     nullptr, 0),
          "rotateScp03: load current DEK into static ctx");
}

// Port of genKCVandEncryptKey(): KCV = AES-CBC(plainKey, IV=0, {0x01}*16)[0:3];
// encrypted = AES-CBC(currentDEK, IV=0, plainKey).  Uses the host crypto path,
// exactly as the demo, so the math is identical to NXP's reference.
void genKcvAndEncryptKey(Session &s, const uint8_t *plainKey, uint8_t encOut[kScpKeyLen],
                         uint8_t kcvOut[CRYPTO_KEY_CHECK_LEN]) {
    ex_sss_boot_ctx_t *pCtx = s.bootCtx();
    NXSCP03_StaticCtx_t *st = staticCtx(s);

    sss_object_t keyObj{};
    sss_symmetric_t symm{};
    const uint32_t kHostKeyId = 0x544D5031; // "TMP1" – transient host scratch id

    auto cleanup = [&] {
        if (symm.keyObject)
            sss_host_symmetric_context_free(&symm);
        sss_host_key_object_free(&keyObj);
    };

    check(sss_host_key_object_init(&keyObj, &pCtx->host_ks),
          "genKcvAndEncryptKey: key_object_init");
    sss_status_t rc = sss_host_key_object_allocate_handle(&keyObj, kHostKeyId, kSSS_KeyPart_Default,
                                                          kSSS_CipherType_AES, kScpKeyLen,
                                                          kKeyObject_Mode_Transient);
    if (rc != kStatus_SSS_Success) {
        sss_host_key_object_free(&keyObj);
        check(rc, "allocate_handle");
    }

    uint8_t iv[16] = {};

    // 1) KCV over a block of 0x01 with the *new* plaintext key
    uint8_t refOnes[kScpKeyLen];
    std::memset(refOnes, 1, sizeof(refOnes));
    uint8_t kcvFull[kScpKeyLen] = {};
    rc = sss_host_key_store_set_key(&pCtx->host_ks, &keyObj, plainKey, kScpKeyLen, kScpKeyLen * 8,
                                    nullptr, 0);
    if (rc != kStatus_SSS_Success) {
        cleanup();
        check(rc, "set new key (KCV)");
    }
    rc = sss_host_symmetric_context_init(&symm, &pCtx->host_session, &keyObj,
                                         kAlgorithm_SSS_AES_CBC, kMode_SSS_Encrypt);
    if (rc != kStatus_SSS_Success) {
        cleanup();
        check(rc, "symm_init (KCV)");
    }
    rc = sss_host_cipher_one_go(&symm, iv, sizeof(iv), refOnes, kcvFull, kScpKeyLen);
    if (rc != kStatus_SSS_Success) {
        cleanup();
        check(rc, "cipher (KCV)");
    }
    std::memcpy(kcvOut, kcvFull, CRYPTO_KEY_CHECK_LEN);

    // 2) wrap the new key with the current DEK
    uint8_t dek[kScpKeyLen] = {};
    size_t dekLen = sizeof(dek), dekBits = sizeof(dek) * 8;
    rc = sss_host_key_store_get_key(&pCtx->host_ks, &st->Dek, dek, &dekLen, &dekBits);
    if (rc != kStatus_SSS_Success) {
        cleanup();
        check(rc, "get current DEK");
    }
    rc = sss_host_key_store_set_key(&pCtx->host_ks, &keyObj, dek, st->key_len,
                                    static_cast<size_t>(st->key_len) * 8, nullptr, 0);
    if (rc != kStatus_SSS_Success) {
        cleanup();
        check(rc, "set DEK");
    }
    rc = sss_host_symmetric_context_init(&symm, &pCtx->host_session, &keyObj,
                                         kAlgorithm_SSS_AES_CBC, kMode_SSS_Encrypt);
    if (rc != kStatus_SSS_Success) {
        cleanup();
        check(rc, "symm_init (wrap)");
    }
    rc = sss_host_cipher_one_go(&symm, iv, sizeof(iv), plainKey, encOut, kScpKeyLen);
    if (rc != kStatus_SSS_Success) {
        cleanup();
        check(rc, "cipher (wrap)");
    }

    // scrub the DEK copy off the stack
    volatile uint8_t *vp = dek;
    for (size_t i = 0; i < sizeof(dek); ++i)
        vp[i] = 0;
    cleanup();
}

// Port of createKeyData(): one key block ->
//   [type 0x88][len key_len+1][key_len][enc key][CRYPTO_KEY_CHECK_LEN][kcv]
// Returns bytes written and copies the 3-byte KCV out for response verification.
size_t createKeyData(Session &s, const uint8_t *key, uint8_t *dst,
                     uint8_t kcvOut[CRYPTO_KEY_CHECK_LEN]) {
    dst[0] = PUT_KEYS_KEY_TYPE_CODING_AES; // 0x88
    dst[1] = kScpKeyLen + 1;               // length of 'AES key data'
    dst[2] = kScpKeyLen;                   // length of 'AES key'
    genKcvAndEncryptKey(s, key, &dst[3], kcvOut);
    dst[3 + kScpKeyLen] = CRYPTO_KEY_CHECK_LEN;
    std::memcpy(&dst[3 + kScpKeyLen + 1], kcvOut, CRYPTO_KEY_CHECK_LEN);
    return 3 + kScpKeyLen + 1 + CRYPTO_KEY_CHECK_LEN; // 23
}

} // namespace

// Platform SCP03 key rotation (port of NXP tp_PlatformKeys)

void rotateScp03(Session &s, const Scp03KeySet &newKeys, bool dryRun) {
    NXSCP03_StaticCtx_t *st = staticCtx(s);
    const uint8_t keyVer = st->keyVerNo; // KVN to replace (e.g. 0x0B on 07.02)

    // PUT KEY requires the SCP03 channel at full security (C-MAC + C-DECRYPTION
    // = 0x33); the wrapped key data must be command-encrypted.  Reads succeed at
    // lower levels, so fail fast here with a clear message rather than letting
    // the card reject with an opaque 0x6982.
    auto *dyn = s.bootCtx()->se05x_open_ctx.auth.ctx.scp03.pDyn_ctx;
    const unsigned secLevel = dyn ? dyn->SecurityLevel : 0xFF;
    LOG_DEBUG("rotateScp03: SCP03 SecurityLevel = 0x%02X (need 0x33)\n", secLevel);
    if (secLevel != 0x33)
        throw std::runtime_error(
            "rotateScp03: SCP03 security level is 0x" +
            [secLevel] {
                char b[4];
                std::snprintf(b, sizeof(b), "%02X", secLevel);
                return std::string(b);
            }() +
            ", but PUT KEY needs 0x33 (C-MAC + C-DECRYPTION); open the session at full "
            "security before rotating");

    // Make sure the current DEK is available to wrap the new keys.
    loadCurrentDek(s);

    LOG_INFO("rotateScp03: updating PlatformSCP keys at version 0x%02X\n", keyVer);

    // Build the GP PUT KEY body:  new_kvn | ENC block | MAC block | DEK block
    uint8_t cmdBuf[128] = {};
    size_t len = 0;
    cmdBuf[len++] = keyVer; // new key version (unchanged)

    // Expected response echo = new_kvn | KCV(enc) | KCV(mac) | KCV(dek)
    uint8_t expected[1 + 3 * CRYPTO_KEY_CHECK_LEN] = {};
    size_t expLen = 0;
    expected[expLen++] = keyVer;

    const uint8_t *keys[3] = {newKeys.enc, newKeys.mac, newKeys.dek};
    for (const uint8_t *k : keys) {
        uint8_t kcv[CRYPTO_KEY_CHECK_LEN];
        len += createKeyData(s, k, &cmdBuf[len], kcv);
        std::memcpy(&expected[expLen], kcv, CRYPTO_KEY_CHECK_LEN);
        expLen += CRYPTO_KEY_CHECK_LEN;
    }

    if (dryRun) {
        LOG_INFO("rotateScp03 DRY-RUN: PUT KEY body built (%zu bytes), not sent\n", len);
        return;
    }

    // Send over the active SCP03 session (S-ENC + C-MAC applied by the transport).
    auto *se05xSession = reinterpret_cast<sss_se05x_session_t *>(s.session());
    const tlvHeader_t hdr = {{GP_CLA_BYTE, GP_INS_PUTKEY, keyVer, GP_P2_NEW_MULTI(keyVer)}};
    uint8_t rsp[64] = {};
    size_t rspLen = sizeof(rsp);

    LOG_DEBUG("rotateScp03: sending PUT KEY (%zu bytes) over SCP03\n", len);
    smStatus_t txr = DoAPDUTxRx_s_Case4(&se05xSession->s_ctx, &hdr, cmdBuf, len, rsp, &rspLen);

    char swbuf[8];
    if (txr != SM_OK) {
        std::snprintf(swbuf, sizeof(swbuf), "%04X", static_cast<unsigned>(txr));
        throw std::runtime_error(std::string("rotateScp03: PUT KEY transport failed (SW=0x") +
                                 swbuf + " - " + swMeaning(txr) + ")");
    }
    if (rspLen < expLen + 2)
        throw std::runtime_error("rotateScp03: PUT KEY response too short (" +
                                 std::to_string(rspLen) + " bytes)");

    // Trailing SW from the response body.
    smStatus_t sw = static_cast<smStatus_t>((rsp[rspLen - 2] << 8) | rsp[rspLen - 1]);
    if (sw != SM_OK) {
        std::snprintf(swbuf, sizeof(swbuf), "%04X", static_cast<unsigned>(sw));
        throw std::runtime_error(std::string("rotateScp03: PUT KEY rejected (SW=0x") + swbuf +
                                 " - " + swMeaning(sw) + ")");
    }

    // Confirm the SE stored exactly the keys we sent (KVN + each KCV).
    if (std::memcmp(rsp, expected, expLen) != 0)
        throw std::runtime_error(
            "rotateScp03: key-check-value mismatch - the SE response does not match the "
            "rotated keys; rotation NOT confirmed");

    LOG_OK("PlatformSCP03 keys rotated and KCV-verified at version 0x%02X; "
           "persist the new keys and reopen to authenticate with them\n",
           keyVer);
}

// --- Scp03Admin: one-call rotation entry point ---

std::unique_ptr<Scp03Admin> Scp03Admin::open(const char *port) {
    std::unique_ptr<Scp03Admin> a(new Scp03Admin());
    a->conn_ = std::make_unique<SssConnection>(port, /*selectApplet=*/false);
    return a;
}

Scp03Admin::~Scp03Admin() = default;

void Scp03Admin::rotate(const Scp03KeySet &newKeys, bool dryRun, const char *keyFile) {
    rotateScp03(conn_->session(), newKeys, dryRun);
    if (dryRun || !keyFile)
        return;
    Scp03KeyFile::write(keyFile, newKeys); // atomic; backs up to <keyFile>.bak
}

} // namespace se05x
