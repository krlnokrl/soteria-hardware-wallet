#ifndef SECURE_STORAGE_H
#define SECURE_STORAGE_H

#include <Wire.h>
#include <Adafruit_SSD1306.h>
#include "Key.h"

#define EEPROM_ADDRESS 0x50  // I2C address of the EEPROM
#define KEY_STORAGE_SIZE 6  // Number of keys that can be stored

// Storage Offsets
#define KEY_STORAGE_OFFSET 0x0000
#define FLAG_STORAGE_OFFSET 0x0200
#define NAME_STORAGE_OFFSET 0x0210
#define NAME_LENGTH 8
#define NAME_STORAGE_SIZE 8

class SecureStorage {
private:
    uint8_t _eepromAddress;

public:
    SecureStorage(uint8_t eepromAddress = EEPROM_ADDRESS) : _eepromAddress(eepromAddress) {}
    
    // Store a key in EEPROM
    void storeKey(uint8_t index, const Key &key) {
        if (index >= KEY_STORAGE_SIZE) return;
        
        uint8_t *data = (uint8_t *)&key;
        uint16_t address = KEY_STORAGE_OFFSET + index * sizeof(Key);
        
        writeBlock(address, data, sizeof(Key));
    }

    // Read a key from EEPROM
    void getKey(uint8_t index, Key &key) {
        if (index >= KEY_STORAGE_SIZE) return;
        
        uint8_t *data = (uint8_t *)&key;
        uint16_t address = KEY_STORAGE_OFFSET + index * sizeof(Key);
        
        readBlock(address, data, sizeof(Key));
    }

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

    // Write a name string to EEPROM
    void writeName(uint8_t index, const char *name) {
        if (index >= NAME_STORAGE_SIZE) return;
        
        uint16_t address = NAME_STORAGE_OFFSET + index * NAME_LENGTH;
        writeBlock(address, (uint8_t *)name, strlen(name) + 1); // Write null terminator
    }

    // Read a name string from EEPROM
    void readName(uint8_t index, char *buffer, uint8_t maxLength) {
        if (index >= NAME_STORAGE_SIZE) return;

        uint16_t address = NAME_STORAGE_OFFSET + index * NAME_LENGTH;
        readBlock(address, (uint8_t *)buffer, maxLength);
    }

    void getName(uint8_t index, String &name) {
        char buffer[NAME_LENGTH + 1];
        readName(index, buffer, NAME_LENGTH);
        name = String(buffer);
    }

private:
    // Write a block of data to EEPROM
    void writeBlock(uint16_t address, const uint8_t *data, uint16_t length) {
        Wire.beginTransmission(_eepromAddress);
        Wire.write((uint8_t)(address >> 8));
        Wire.write((uint8_t)(address & 0xFF));
        
        for (uint16_t i = 0; i < length; i++) {
            Wire.write(data[i]);
        }
        
        Wire.endTransmission();
    }

    // Read a block of data from EEPROM
    void readBlock(uint16_t address, uint8_t *buffer, uint16_t length) {
        Wire.beginTransmission(_eepromAddress);
        Wire.write((uint8_t)(address >> 8));
        Wire.write((uint8_t)(address & 0xFF));
        Wire.endTransmission();
        
        Wire.requestFrom(_eepromAddress, length);
        
        for (uint16_t i = 0; i < length; i++) {
            if (Wire.available()) {
                buffer[i] = Wire.read();
            } else {
                break;
            }
        }
    }
};

#endif // SECURE_STORAGE_H