#include "SecureStorage.h"

// The EEPROM address is set by the constructor (SecureStorage(uint8_t)).
// This helper is kept for compatibility; Wire is initialised by the caller/display.
void SecureStorage_Init(SecureStorage &storage, uint8_t eepromAddress) {
    (void)storage;
    (void)eepromAddress;
}
