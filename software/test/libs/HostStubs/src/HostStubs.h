#pragma once
// Controls for the host stand-ins, used by the tests.
#include <stdint.h>
#include <vector>

// Erased EEPROM, empty USB queues, no button pressed, ATECC as below.
void hostReset();

// `pin` reads high after `after` more reads of it, for `reads` reads.
void hostPress(int pin, int after, int reads);

// FIDO2 master secret the wallet holds (nullptr: no wallet).
void hostSetFidoSecret(const uint8_t *secret);

// USB HID reports: host -> device, and device -> host (false if none).
void hostUsbOut(const uint8_t pkt[64]);
bool hostUsbIn(uint8_t pkt[64]);

// Fake ATECC508A at 0x60: asleep, present, unlocked factory-like config
// zone (made-up serial number); each command NAKs 2 polls while it
// "executes".
void hostAteccReset();
// As env:seprov leaves it: planned slot map, both zones locked, pairing
// secret P and stretch secret W, factory PIN/PUK verifiers.
void hostAteccProvision(const uint8_t pairing[32], const uint8_t stretch[32]);
void hostAteccSetPresent(bool present);
void hostAteccSetBusyPolls(int polls);
// Flip a CRC bit in each of the next `responses` responses.
void hostAteccCorrupt(int responses);
uint8_t *hostAteccConfig();
// Opcodes of every well-formed command the chip received.
const std::vector<uint8_t> &hostAteccOpcodes();
