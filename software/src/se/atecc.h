#ifndef ATECC_H
#define ATECC_H

// Minimal I2C driver for the ATECC508A secure element (U4), on the same
// bus as the EEPROM and the OLED. See docs/ATECC_PLAN.md.
//
// Every public call is one complete session: wake, command(s), sleep. The
// chip forgets TempKey when it sleeps, so Nonce/GenDig and the command
// that uses them always run in the same session. Transient bus errors are
// retried with a fresh session.
//
// Host-side computations (TempKey, GenDig digest, write MAC) follow the
// ATECC508A datasheet; cross-checked with Microchip's cryptoauthlib
// (lib/host/atca_host.c) and Coldcard's ATECC508A driver.
#include <Arduino.h>
#include <Wire.h>

#define ATECC_ADDRESS     0x60   // 7-bit; 0xC0 in Microchip's 8-bit notation
#define ATECC_CONFIG_SIZE 128
#define ATECC_REV_508A    0x50   // Info revision byte 2 of an ATECC508A

// Status byte of a 4-byte chip response, plus driver-side errors (0xF0+,
// never sent by the chip).
enum AteccStatus : uint8_t {
    ATECC_SUCCESS       = 0x00,
    ATECC_CHECKMAC_FAIL = 0x01,
    ATECC_PARSE_ERROR   = 0x03,
    ATECC_ECC_FAULT     = 0x05,
    ATECC_EXEC_ERROR    = 0x0F,
    ATECC_AFTER_WAKE    = 0x11,
    ATECC_WATCHDOG      = 0xEE,
    ATECC_COMM_ERROR    = 0xFF,   // chip saw a bad CRC
    ATECC_NO_DEVICE     = 0xF0,   // no ACK / no wake token
    ATECC_TIMEOUT       = 0xF1,   // still busy after the max execution time
    ATECC_BAD_RESPONSE  = 0xF2,   // wrong length or CRC in the response
};

const char *ateccStatusName(uint8_t status);

class Atecc {
public:
    explicit Atecc(TwoWire &wire = Wire, uint8_t address = ATECC_ADDRESS)
        : _wire(wire), _address(address) {}

    // Wake the chip (it starts asleep and falls asleep again ~1.3 s after
    // waking, watchdog). True once it answered with the wake token.
    bool wake();
    // Sleep clears all volatile state; idle keeps TempKey.
    void sleep();
    void idle();

    // Info (mode 0): 4 revision bytes, rev[2] == ATECC_REV_508A.
    uint8_t info(uint8_t rev[4]);
    // The whole 128-byte config zone (readable whether locked or not).
    uint8_t readConfig(uint8_t config[ATECC_CONFIG_SIZE]);

    // Host randomness mixed into every Nonce (NumIn), e.g. A0 noise.
    void mixHostEntropy(const uint8_t *data, size_t len);

    // 32 random bytes. Before the config lock the chip returns a fixed
    // pattern (FF FF 00 00 ...), which callers must reject.
    uint8_t random(uint8_t out[32]);

    /* Data zone, after the data lock ------------------------------- */

    // Clear 32-byte read of a slot block (non-secret slots only).
    uint8_t read32(uint8_t slot, uint8_t block, uint8_t out[32]);
    // Encrypted read/write of a 32-byte block, authorised by the key in
    // keySlot (Nonce + GenDig). Wrong key: garbage (read) / error (write).
    uint8_t readEncrypted(uint8_t slot, uint8_t block, uint8_t keySlot,
                          const uint8_t key[32], uint8_t out[32]);
    uint8_t writeEncrypted(uint8_t slot, uint8_t block, uint8_t keySlot,
                           const uint8_t key[32], const uint8_t data[32]);
    // MAC (mode 0x40: challenge from input, full serial number included)
    // with the key in slot; one-way, the key never leaves the chip.
    uint8_t mac(uint8_t slot, const uint8_t challenge[32], uint8_t out[32]);
    // io = MAC(slot, io), `rounds` times (key stretching; several rounds
    // per wake session, well inside the watchdog).
    uint8_t macChain(uint8_t slot, uint8_t io[32], uint16_t rounds);
    // Monotonic counter 0 or 1: read, or increment and return the new value.
    uint8_t counter(uint8_t id, bool increment, uint32_t &value);
    // New random P-256 private key in slot / public key of slot (X | Y).
    uint8_t genKey(uint8_t slot, uint8_t pub[64]);
    uint8_t publicKey(uint8_t slot, uint8_t pub[64]);

    /* Provisioning only (env:seprov_*) ----------------------------- */

    // Write the SlotConfig and KeyConfig words of config (unlocked config
    // zone only); every other config byte is left as it is.
    uint8_t writeSlotConfig(const uint8_t config[ATECC_CONFIG_SIZE]);
    // Clear write of a slot in whole 32-byte blocks (unlocked data zone
    // only); the tail of 36/72-byte slots is not written.
    uint8_t writeSlotClear(uint8_t slot, const uint8_t *data, uint16_t len);
    // IRREVERSIBLE. Config lock checks crc over the 128 config bytes; the
    // data zone is locked without a CRC (every write was CRC-checked).
    uint8_t lockConfig(uint16_t crc);
    uint8_t lockData();

    // 9-byte serial number (cached after the first call).
    uint8_t serial(uint8_t sn[9]);

    // CRC-16 of the command/response packets (poly 0x8005, bits LSB first,
    // init 0); sent little-endian.
    static uint16_t crc16(const uint8_t *data, size_t len);

private:
    uint8_t execute(uint8_t opcode, uint8_t param1, uint16_t param2,
                    const uint8_t *data, uint8_t len,
                    uint8_t *out, uint8_t outLen);
    uint8_t executeStatus(uint8_t opcode, uint8_t param1, uint16_t param2,
                          const uint8_t *data, uint8_t len);
    uint8_t receive(uint8_t *out, uint8_t outLen, uint16_t maxExecMs);
    uint8_t loadSerial();
    uint8_t authorize(uint8_t keySlot, const uint8_t key[32], uint8_t digest[32]);
    void nextNumIn(uint8_t numIn[20]);

    TwoWire &_wire;
    uint8_t _address;
    uint8_t _sn[9] = { 0 };
    bool _haveSn = false;
    uint8_t _pool[32] = { 0 };   // host entropy pool for NumIn
    uint32_t _nonces = 0;
};

#endif // ATECC_H
