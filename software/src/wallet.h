#ifndef __WALLET_H_
#define __WALLET_H_
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Wire.h>
#include <Bitcoin.h>
#include <SecureStorage.h>

//#include <SecureIC.h>
//#include <ethers.h>

#include "display/display_fx.h"
#include "buttons.h"
#include "crypto/btchd.h"

#define GEN_FLAG 0xFEED

// Button pins (active high)
#define YES 38
#define NO 2

// EEPROM key slot holding the FIDO2 master secret (stored unencrypted:
// a security key must work without the wallet PIN).
#define FIDO_KEY_SLOT 4

// Confirmations requested over USB (FIDO2 user presence, host protocol
// prompts) give up after this long without a button press, so an
// unattended request cannot block the device indefinitely.
#define USER_CONFIRM_TIMEOUT_MS 60000UL

// Timeout for askYesNo() / askPin(): each prompt (each PIN digit) gives
// up after ms without an answer. 0 = wait forever (on-device menus).
void setPromptTimeout(uint32_t ms);

// True if the last askYesNo() / askPin() gave up because of the timeout.
bool promptTimedOut();

int RNGpin(uint8_t *dest, unsigned size);

void generateWallet(Adafruit_SSD1306 &display,SecureStorage &eeprom);

String getWordsInString(String data, char separator, int index);

// Outcome of a signing request. Every signer shows the request on the
// display, asks for confirmation and the PIN, and only then signs.
enum WalletStatus {
  WALLET_OK = 0,
  WALLET_REJECTED,    // user pressed NO
  WALLET_WRONG_PIN,
  WALLET_INVALID,     // malformed or unsupported input
  WALLET_TOO_LARGE,   // result does not fit the output buffer
};

// Sign every (P2PKH) input of a raw legacy transaction; out = signed tx.
WalletStatus signBtcTx(Adafruit_SSD1306 &display, const uint8_t *raw, size_t len, Key k,
                       bool testnet, uint8_t *out, size_t cap, size_t *outLen);

// Blind-sign a 32-byte hash; sig = r | s | recovery id.
WalletStatus signEthHash(Adafruit_SSD1306 &display, const uint8_t hash[32], Key k, uint8_t sig[65]);

// Parse, show and sign an unsigned EIP-155 / EIP-1559 transaction;
// out = signed serialized transaction.
WalletStatus signEthTx(Adafruit_SSD1306 &display, const uint8_t *raw, size_t len, Key k,
                       uint8_t sig[65], uint8_t *out, size_t cap, size_t *outLen);

// EIP-191 personal_sign of msg.
WalletStatus signEthMessage(Adafruit_SSD1306 &display, const uint8_t *msg, size_t len, Key k,
                            uint8_t sig[65]);

// Review a parsed, checked PSBT (psbtReview() == PSBT_OK) on the device,
// unlock the HD root with the PIN and add signatures.
WalletStatus signPsbt(Adafruit_SSD1306 &display, PSBT &psbt, const HdRecord &rec, bool testnet,
                      const PsbtSummary &sum, uint8_t *signedInputs);

// Two-step confirmation on the device; true if the wallet was erased.
bool eraseDevice(Adafruit_SSD1306 &display, SecureStorage &eeprom);

void xorKey(Key &k, uint8_t *pin);

// Decrypt k with pin and check it against the stored public key.
// Returns false (k is then garbage) when the PIN is wrong.
bool unlockKey(Key &k, uint8_t *pin);

// Read the FIDO2 master secret; false if this wallet has none.
bool loadFidoSecret(SecureStorage &eeprom, uint8_t secret[32]);

// Build a human readable address string from a stored Key.
// For BTC/BTCT this is the base58 legacy address; for ETH it is the
// keccak256-derived, EIP-55 checksummed address.
String keyAddress(const Key &k, bool testnet);

// Receive addresses (#0) of the stored wallet. Deriving them takes
// seconds on this MCU, so they are computed on first use and cached
// until the wallet changes (generate / erase).
struct WalletAddresses {
  bool segwit;              // false: wallet predates SegWit (no HD record)
  char btc[96];             // native SegWit, if segwit
  char btcTest[96];
  char btcLegacy[40];       // P2PKH from the legacy key slots
  char btcTestLegacy[40];
  char eth[43];             // EIP-55
};
const WalletAddresses &walletAddresses(SecureStorage &eeprom);
void forgetWalletAddresses();

// Derive a checksummed Ethereum address (EIP-55) from a stored Key's
// public key.
size_t ethAddressFromKey(const Key &k, char out[43]);

boolean askYesNo(Adafruit_SSD1306 &display);

// Block until a button is pressed (no timeout; on-device flows).
Button waitButton();

// Full-screen text for ms milliseconds.
void showMessage(Adafruit_SSD1306 &display, const char *text, uint32_t ms);

// Returns false if the user aborted with NO (pin is then incomplete).
bool askPin(Adafruit_SSD1306 &display, uint8_t *pin);

#endif