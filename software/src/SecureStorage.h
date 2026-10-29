#ifndef SECURE_STORAGE_H
#define SECURE_STORAGE_H

#include <Wire.h>
#include <Adafruit_SSD1306.h>
#include "Key.h"

#define EEPROM_ADDRESS 0x50  // I2C address of the EEPROM
#define EEPROM_PAGE_SIZE 32  // GT24C64A write page; writes must not cross it
#define EEPROM_WRITE_TIMEOUT_MS 10  // max internal write cycle (datasheet: 5 ms)

// Storage Offsets
#define LEGACY_KEYS_OFFSET  0x0000  // key slots of firmware < 0.5.0 (secret!)
#define LEGACY_KEYS_SIZE    0x0200
#define FLAG_STORAGE_OFFSET 0x0200
#define NAME_STORAGE_OFFSET 0x0210
#define NAME_LENGTH 8
#define NAME_STORAGE_SIZE 8
#define HD_RECORD_OFFSET 0x0280     // HdRecord (331 bytes)
#define SE_RECORD_OFFSET 0x0400     // SeRecord (48 bytes)

class SecureStorage {
private:
    uint8_t _eepromAddress;

public:
    SecureStorage(uint8_t eepromAddress = EEPROM_ADDRESS) : _eepromAddress(eepromAddress) {}
    
    // Write a flag value to EEPROM
    void writeFlag(uint8_t index, uint16_t value) {
        uint16_t address = FLAG_STORAGE_OFFSET + index * sizeof(uint16_t);
        writeBlock(address, (uint8_t *)&value, sizeof(uint16_t));
    }

    // Read a flag value from EEPROM
    uint16_t readFlag(uint8_t index) {
        uint16_t value = 0;
        uint16_t address = FLAG_STORAGE_OFFSET + index * sizeof(uint16_t);
        readBlock(address, (uint8_t *)&value, sizeof(uint16_t));
        return value;
    }

    void getFlag(uint8_t index, uint16_t &value) {
        value = readFlag(index);
    }

    // Write a name string to EEPROM. The slot is NAME_LENGTH bytes; longer
    // names are truncated and shorter ones are NUL-padded, so a name can
    // never spill into the neighbouring slot.
    void writeName(uint8_t index, const char *name) {
        if (index >= NAME_STORAGE_SIZE) return;

        uint8_t slot[NAME_LENGTH] = {0};
        strncpy((char *)slot, name, NAME_LENGTH);
        uint16_t address = NAME_STORAGE_OFFSET + index * NAME_LENGTH;
        writeBlock(address, slot, NAME_LENGTH);
    }

    // Read a name string from EEPROM
    void readName(uint8_t index, char *buffer, uint8_t maxLength) {
        if (index >= NAME_STORAGE_SIZE) return;

        uint16_t address = NAME_STORAGE_OFFSET + index * NAME_LENGTH;
        readBlock(address, (uint8_t *)buffer, maxLength);
    }

    void getName(uint8_t index, String &name) {
        char buffer[NAME_LENGTH + 1] = {0};
        readName(index, buffer, NAME_LENGTH);
        buffer[NAME_LENGTH] = 0;   // a full 8-char name has no terminator
        // Erased EEPROM reads back as 0xFF: treat it as "no name".
        if ((uint8_t)buffer[0] == 0xFF) buffer[0] = 0;
        name = String(buffer);
    }

    // Public wallet data; false if there is no wallet.
    bool readHd(HdRecord &rec) {
        readBlock(HD_RECORD_OFFSET, (uint8_t *)&rec, sizeof(rec));
        rec.xpub[0][HD_XPUB_LEN - 1] = 0;
        rec.xpub[1][HD_XPUB_LEN - 1] = 0;
        return rec.magic == HD_RECORD_MAGIC;
    }

    void writeHd(const HdRecord &rec) {
        writeBlock(HD_RECORD_OFFSET, (const uint8_t *)&rec, sizeof(rec));
    }

    void eraseHd() {
        HdRecord blank;
        memset(&blank, 0xFF, sizeof(blank));
        writeHd(blank);
    }

    // Overwrite the private-key slots firmware < 0.5.0 kept in the EEPROM
    // (masked only with the PIN); this firmware never reads them.
    void eraseLegacyKeys() {
        uint8_t blank[EEPROM_PAGE_SIZE];
        memset(blank, 0xFF, sizeof(blank));
        for (uint16_t a = LEGACY_KEYS_OFFSET; a < LEGACY_KEYS_OFFSET + LEGACY_KEYS_SIZE; a += EEPROM_PAGE_SIZE) {
            writeBlock(a, blank, sizeof(blank));
        }
    }

    // Secure element pairing; false if the device was never provisioned.
    bool readSe(SeRecord &rec) {
        readBlock(SE_RECORD_OFFSET, (uint8_t *)&rec, sizeof(rec));
        return rec.magic == SE_RECORD_MAGIC;
    }

    void writeSe(const SeRecord &rec) {
        writeBlock(SE_RECORD_OFFSET, (const uint8_t *)&rec, sizeof(rec));
    }

private:
    // Write a block of data to EEPROM. The chip only latches one page per
    // write cycle and wraps around inside the page, so split the block at
    // page boundaries and wait for each internal write cycle to finish
    // (the chip NAKs its address while busy).
    void writeBlock(uint16_t address, const uint8_t *data, uint16_t length) {
        while (length > 0) {
            uint16_t chunk = EEPROM_PAGE_SIZE - (address % EEPROM_PAGE_SIZE);
            if (chunk > length) chunk = length;

            Wire.beginTransmission(_eepromAddress);
            Wire.write((uint8_t)(address >> 8));
            Wire.write((uint8_t)(address & 0xFF));
            Wire.write(data, chunk);
            Wire.endTransmission();
            waitWriteDone();

            address += chunk;
            data += chunk;
            length -= chunk;
        }
    }

    // ACK polling: the EEPROM ignores its address until the write is done.
    void waitWriteDone() {
        uint32_t start = millis();
        do {
            Wire.beginTransmission(_eepromAddress);
            if (Wire.endTransmission() == 0) return;
        } while (millis() - start < EEPROM_WRITE_TIMEOUT_MS);
    }

    // Read a block of data from EEPROM, in chunks that fit the Wire
    // receive buffer (blocks like HdRecord exceed it).
    void readBlock(uint16_t address, uint8_t *buffer, uint16_t length) {
        while (length > 0) {
            uint8_t chunk = length > EEPROM_PAGE_SIZE ? EEPROM_PAGE_SIZE : (uint8_t)length;
            Wire.beginTransmission(_eepromAddress);
            Wire.write((uint8_t)(address >> 8));
            Wire.write((uint8_t)(address & 0xFF));
            Wire.endTransmission();

            Wire.requestFrom(_eepromAddress, chunk);
            for (uint8_t i = 0; i < chunk; i++) {
                buffer[i] = Wire.available() ? Wire.read() : 0xFF;
            }
            address += chunk;
            buffer += chunk;
            length -= chunk;
        }
    }
};

#endif // SECURE_STORAGE_H
