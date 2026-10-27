#pragma once
// Controls for the host stand-ins, used by the tests.
#include <stdint.h>

// Erased EEPROM, empty USB queues, no button pressed.
void hostReset();

// `pin` reads high after `after` more reads of it, for `reads` reads.
void hostPress(int pin, int after, int reads);

// USB HID reports: host -> device, and device -> host (false if none).
void hostUsbOut(const uint8_t pkt[64]);
bool hostUsbIn(uint8_t pkt[64]);
