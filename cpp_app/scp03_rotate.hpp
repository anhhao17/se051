/**
 * @file scp03_rotate.hpp
 * @brief SE05x Platform SCP03 static-key rotation (GP PUT KEY).
 *
 * Isolated from se05x_provision.* because channel-key rotation is a distinct
 * responsibility from SE object management (UID / certificates / RSA keys):
 * it speaks the GlobalPlatform PUT KEY protocol against the ISD and reaches
 * into the SCP03 static context and host-crypto session, which the ordinary
 * provisioning helpers never touch.
 *
 * Direct port of NXP's se05x_TP_PlatformSCP03keys demo (tp_PlatformKeys /
 * createKeyData / genKCVandEncryptKey).  128-bit keys only.
 */

#pragma once
#include "se05x_crypto.hpp"
#include <cstdint>

namespace se05x {

/**
 * @brief A full set of 128-bit Platform SCP03 static keys.
 *
 * Mirrors the three keys the SE05x ISD holds for the PlatformSCP channel.
 * 16-byte keys only (matches the demo's ROTATE_PLATFORMSCP03_128BITLEN=1).
 */
struct Scp03KeySet {
    uint8_t enc[16]; ///< S-ENC
    uint8_t mac[16]; ///< S-MAC
    uint8_t dek[16]; ///< DEK
};

/**
 * @brief Rotate the SE05x Platform SCP03 static keys (GP PUT KEY).
 *
 * Each new key is wrapped with the *current* DEK and a KCV is appended, then a
 * single GP PUT KEY APDU is sent over the active SCP03 channel.  The SE echoes
 * back [KVN || KCV...]; rotation is only treated as successful if that echo
 * matches the locally computed KCVs.  The new key version number is left
 * unchanged (P1 = current KVN, e.g. 0x0B on SE05x 07.02), as the demo does.
 *
 * @warning IRREVERSIBLE.  After success the SE only accepts the new keys; the
 *          current session keeps working (it uses already-derived session
 *          keys) but the *next* session must authenticate with the new keys.
 *          Persist @p newKeys to your SCP03 key file before reopening.
 *
 * @note Preconditions (handled internally where possible):
 *        - The SCP03 channel must already be open (this runs over it).
 *        - The *current* DEK is read from the key file named by
 *          $EX_SSS_BOOT_SCP03_PATH and loaded into the static context, because
 *          a standard ex_sss_boot_open leaves pStatic_ctx->Dek zeroed.
 *        - The session must be talking to the ISD.  If your management session
 *          has the SE05x applet selected and PUT KEY is rejected (SW 6985 /
 *          6D00), open a session with se05x_open_ctx.skip_select_applet = 1.
 *
 * @param s        Active SCP03 session.
 * @param newKeys  The new ENC/MAC/DEK to install.
 * @param dryRun   If true, build and log the APDU but do not send it.
 * @throws CryptoError / std::runtime_error on any failure (rotation aborted).
 */
void rotateScp03(Session &s, const Scp03KeySet &newKeys, bool dryRun = false);

} // namespace se05x
