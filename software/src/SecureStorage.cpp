#include "SecureStorage.h"

// Initialize the EEPROM
// Constructor implementation moved to header to avoid redefinition
void SecureStorage_Init(SecureStorage &storage, uint8_t eepromAddress) {
    Wire.begin();
    storage._eepromAddress = eepromAddress;
}
