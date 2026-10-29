#ifndef SE_LAYOUT_H
#define SE_LAYOUT_H

// ATECC508A config zone layout and the planned Soteria slot map
// (docs/ATECC_PLAN.md). The plan is data only in phase 1: nothing writes
// it to the chip yet. Bit layouts follow the ATECC508A datasheet; check
// them against it again before the irreversible config lock (phase 2).
#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Config zone (128 bytes)                                             */
/* ------------------------------------------------------------------ */

#define SE_CFG_SN0        0    // SN[0:3]
#define SE_CFG_REVNUM     4    // RevNum[4]
#define SE_CFG_SN4        8    // SN[4:8]
#define SE_CFG_I2C_ENABLE 14
#define SE_CFG_I2C_ADDR   16   // 8-bit address (default 0xC0)
#define SE_CFG_OTP_MODE   18
#define SE_CFG_CHIP_MODE  19
#define SE_CFG_SLOT_CFG   20   // SlotConfig[16], 2 bytes LE each
#define SE_CFG_COUNTERS   52   // Counter[0..1], 8 bytes each
#define SE_CFG_LAST_KEY   68   // LastKeyUse[16] (slot 15 use limit)
#define SE_CFG_USER_EXTRA 84
#define SE_CFG_SELECTOR   85
#define SE_CFG_LOCK_VALUE 86   // data + OTP zones: 0x55 = unlocked
#define SE_CFG_LOCK_CFG   87   // config zone:      0x55 = unlocked
#define SE_CFG_SLOT_LOCK  88   // SlotLocked bits (1 = slot NOT locked)
#define SE_CFG_X509       92
#define SE_CFG_KEY_CFG    96   // KeyConfig[16], 2 bytes LE each

#define SE_UNLOCKED 0x55
#define SE_SLOTS    16

inline uint16_t seSlotConfig(const uint8_t *cfg, int slot) {
    return (uint16_t)(cfg[SE_CFG_SLOT_CFG + 2 * slot] | cfg[SE_CFG_SLOT_CFG + 2 * slot + 1] << 8);
}
inline uint16_t seKeyConfig(const uint8_t *cfg, int slot) {
    return (uint16_t)(cfg[SE_CFG_KEY_CFG + 2 * slot] | cfg[SE_CFG_KEY_CFG + 2 * slot + 1] << 8);
}
inline bool seConfigLocked(const uint8_t *cfg) { return cfg[SE_CFG_LOCK_CFG] != SE_UNLOCKED; }
inline bool seDataLocked(const uint8_t *cfg)   { return cfg[SE_CFG_LOCK_VALUE] != SE_UNLOCKED; }
inline bool seSlotLocked(const uint8_t *cfg, int slot) {
    uint16_t bits = (uint16_t)(cfg[SE_CFG_SLOT_LOCK] | cfg[SE_CFG_SLOT_LOCK + 1] << 8);
    return !((bits >> slot) & 1);
}

// 9-byte serial number (SN[0:1] = 01 23 and SN[8] = EE on genuine parts).
inline void seSerial(const uint8_t *cfg, uint8_t sn[9]) {
    memcpy(sn, cfg + SE_CFG_SN0, 4);
    memcpy(sn + 4, cfg + SE_CFG_SN4, 5);
}

/* ------------------------------------------------------------------ */
/* SlotConfig / KeyConfig bits                                         */
/* ------------------------------------------------------------------ */

// SlotConfig
#define SC_READ_KEY(k)    ((uint16_t)(k))         // key for encrypted reads
#define SC_NO_MAC         0x0010
#define SC_LIMITED_USE    0x0020
#define SC_ENCRYPT_READ   0x0040
#define SC_IS_SECRET      0x0080
#define SC_WRITE_KEY(k)   ((uint16_t)((k) << 8))
#define SC_WRITE_ENCRYPT  0x4000   // WriteConfig 0100: encrypted Write with WriteKey
#define SC_WRITE_GENKEY   0x2000   // WriteConfig 0010: GenKey only, no Write/PrivWrite
// SlotConfig ReadKey bits of ECC private key slots
#define SC_EXT_SIGN       0x0001   // Sign arbitrary (external) messages
#define SC_INT_SIGN       0x0002   // Sign internally generated messages
#define SC_ECDH           0x0004   // ECDH, result in the clear

// KeyConfig
#define KC_PRIVATE        0x0001
#define KC_PUB_INFO       0x0002
#define KC_TYPE_P256      (4 << 2)
#define KC_TYPE_DATA      (7 << 2) // SHA key or plain data
#define KC_LOCKABLE       0x0020   // Lock(slot) allowed: permanent, never set
#define KC_REQ_RANDOM     0x0040
#define KC_REQ_AUTH       0x0080

/* ------------------------------------------------------------------ */
/* Planned slot map                                                    */
/* ------------------------------------------------------------------ */
// Rules are frozen by the config lock, contents are not: every slot can
// be rewritten (with the PIN, the PUK or the pairing secret) or
// regenerated, no slot is lockable or use-limited.

enum SeSlot {
    SE_SLOT_IDENTITY   = 0,   // P-256 device key (attestation), GenKey
    SE_SLOT_PAIRING    = 1,   // pairing secret P (MCU <-> chip)
    SE_SLOT_PIN        = 2,   // PIN verifier V = stretch(PIN)
    SE_SLOT_PUK        = 3,   // PUK verifier M = stretch(PUK)
    SE_SLOT_STRETCH    = 4,   // stretch secret W, MAC only
    SE_SLOT_FIDO       = 5,   // FIDO2 master secret (seed-derived)
    SE_SLOT_SPARE_KEY1 = 6,   // spare P-256 key
    SE_SLOT_SPARE_KEY2 = 7,   // spare P-256 key
    SE_SLOT_SPARE_DATA = 8,   // spare 416-byte encrypted storage
    SE_SLOT_SEED       = 9,   // wallet root (64 B, also MCU-encrypted)
    SE_SLOT_FW_KEY     = 10,  // firmware signing public key (data; the chip's
                              // Verify takes it in external mode)
    SE_SLOT_FW_POLICY  = 11,  // firmware policy (dev mode, min version)
    SE_SLOT_PIN_COUNT  = 12,  // counter value at the last good PIN
    SE_SLOT_SPARE_SEED = 13,  // spare second seed (hidden wallet)
    SE_SLOT_SPARE_PUB  = 14,  // spare public key
    SE_SLOT_SPARE_15   = 15,  // spare encrypted data
};

struct SeSlotPlan {
    const char *role;
    uint16_t slotConfig;
    uint16_t keyConfig;
};

// Secret, never readable, rewritten encrypted with key k. ReadKey 0xF as
// in Coldcard's 508 layout: ReadKey 0 would make the slot a CheckMac/Copy
// source.
#define SE_HIDDEN(k)     (SC_IS_SECRET | SC_READ_KEY(0xF) | SC_WRITE_KEY(k) | SC_WRITE_ENCRYPT)
// Secret, read and written encrypted with key k (Coldcard's seed slots)
#define SE_SEALED(k)     (SC_IS_SECRET | SC_ENCRYPT_READ | SC_READ_KEY(k) | \
                          SC_WRITE_KEY(k) | SC_WRITE_ENCRYPT)
// Readable in the clear, written encrypted with key k
#define SE_GUARDED(k)    (SC_WRITE_KEY(k) | SC_WRITE_ENCRYPT)
// Private key generated (and regenerable) on the chip, never exported
#define SE_ONCHIP_KEY(u) (SC_IS_SECRET | SC_WRITE_GENKEY | (u))

#define SE_KC_DATA        KC_TYPE_DATA
// Keys used for GenDig (encrypted reads/writes) only after a random Nonce
#define SE_KC_AUTH_KEY    (KC_TYPE_DATA | KC_REQ_RANDOM)
#define SE_KC_PRIVATE_KEY (KC_PRIVATE | KC_PUB_INFO | KC_TYPE_P256)

static const SeSlotPlan SE_PLAN[SE_SLOTS] = {
    { "identity key",   SE_ONCHIP_KEY(SC_EXT_SIGN | SC_INT_SIGN),          SE_KC_PRIVATE_KEY },
    { "pairing P",      SE_HIDDEN(SE_SLOT_PUK),                            SE_KC_AUTH_KEY },
    { "PIN verifier",   SE_HIDDEN(SE_SLOT_PUK),                            SE_KC_AUTH_KEY },
    { "PUK verifier",   SE_HIDDEN(SE_SLOT_PUK),                            SE_KC_AUTH_KEY },
    { "stretch W",      SE_HIDDEN(SE_SLOT_PUK),                            SE_KC_DATA },
    { "FIDO2 secret",   SE_SEALED(SE_SLOT_PAIRING),                        SE_KC_DATA },
    { "spare key 1",    SE_ONCHIP_KEY(SC_EXT_SIGN | SC_INT_SIGN | SC_ECDH), SE_KC_PRIVATE_KEY },
    { "spare key 2",    SE_ONCHIP_KEY(SC_EXT_SIGN | SC_INT_SIGN | SC_ECDH), SE_KC_PRIVATE_KEY },
    { "spare storage",  SE_SEALED(SE_SLOT_PAIRING),                        SE_KC_DATA },
    { "wallet seed",    SE_SEALED(SE_SLOT_PIN),                            SE_KC_DATA },
    { "fw signing key", SE_GUARDED(SE_SLOT_PUK),                           SE_KC_DATA },
    { "fw policy",      SE_GUARDED(SE_SLOT_PUK),                           SE_KC_DATA },
    { "PIN counter",    SE_GUARDED(SE_SLOT_PIN),                           SE_KC_DATA },
    { "spare seed",     SE_SEALED(SE_SLOT_PIN),                            SE_KC_DATA },
    { "spare pubkey",   SE_GUARDED(SE_SLOT_PUK),                           SE_KC_DATA },
    { "spare data",     SE_SEALED(SE_SLOT_PAIRING),                        SE_KC_DATA },
};

// The config zone to lock: the chip's current one (serial, I2C address,
// OTP mode, ChipMode, counters stay as shipped) with the planned
// SlotConfig and KeyConfig words.
inline void seBuildConfig(const uint8_t current[128], uint8_t out[128]) {
    memcpy(out, current, 128);
    for (int s = 0; s < SE_SLOTS; s++) {
        out[SE_CFG_SLOT_CFG + 2 * s]     = (uint8_t)SE_PLAN[s].slotConfig;
        out[SE_CFG_SLOT_CFG + 2 * s + 1] = (uint8_t)(SE_PLAN[s].slotConfig >> 8);
        out[SE_CFG_KEY_CFG + 2 * s]      = (uint8_t)SE_PLAN[s].keyConfig;
        out[SE_CFG_KEY_CFG + 2 * s + 1]  = (uint8_t)(SE_PLAN[s].keyConfig >> 8);
    }
}

// Slot sizes of the ATECC508A data zone.
inline uint16_t seSlotSize(int slot) { return slot < 8 ? 36 : slot == 8 ? 416 : 72; }

#endif // SE_LAYOUT_H
