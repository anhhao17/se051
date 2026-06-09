/**
 * @file sw_decode.hpp
 * @brief Human-readable meanings for ISO 7816 / GlobalPlatform status words.
 *
 * Turns a raw SW (e.g. 0x6982) into a short diagnostic string so log lines and
 * error messages say *why* the SE rejected a command, not just the hex code.
 */

#pragma once

/** @return a short description of @p sw (the low 16 bits), or "unknown SW". */
inline const char *swMeaning(unsigned sw) {
    switch (sw & 0xFFFFu) {
    case 0x9000: return "OK";
    case 0x6982: return "security status not satisfied (SCP03 not established / MAC chain broken / wrong auth)";
    case 0x6985: return "conditions of use not satisfied (e.g. applet selected; PUT KEY needs the ISD)";
    case 0x6A80: return "incorrect data (wrong key data / DEK wrap / KCV)";
    case 0x6A88: return "referenced data not found (wrong key version number)";
    case 0x6A82: return "object/file not found";
    case 0x6A84: return "not enough memory on the SE";
    case 0x6986: return "command not allowed (no current object / wrong state)";
    case 0x6D00: return "instruction (INS) not supported - wrong applet/ISD context";
    case 0x6E00: return "class (CLA) not supported - wrong applet/ISD context";
    case 0x6700: return "wrong length (Lc/Le)";
    case 0x6883: return "last command of chain expected";
    case 0x6581: return "memory failure";
    default:     return "unknown SW";
    }
}
