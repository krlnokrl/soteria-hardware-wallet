#ifndef __WALLET_H_
#define __WALLET_H_
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Wire.h>
#include <Bitcoin.h>
#include <SecureStorage.h>

#include "display/display_fx.h"
#include "buttons.h"
#include "crypto/btchd.h"
#include "se/atecc.h"
#include "se/se_wallet.h"

#define GEN_FLAG 0xFEED

// Button pins (active high)
#define YES 38
#define NO 2

// Confirmations requested over USB (FIDO2 user presence, host protocol
// prompts) give up after this long without a button press, so an
// unattended request cannot block the device indefinitely.
#define USER_CONFIRM_TIMEOUT_MS 60000UL

// The secure element (ATECC508A) holding the wallet secrets.
extern Atecc gAtecc;
extern SeWallet gSe;

// Timeout for askYesNo() / askPin(): each prompt (each PIN digit) gives
// up after ms without an answer. 0 = wait forever (on-device menus).
void setPromptTimeout(uint32_t ms);

// True if the last askYesNo() / askPin() gave up because of the timeout.
bool promptTimedOut();

// A0 noise; only ever used mixed with the chip RNG (walletRandom).
int RNGpin(uint8_t *dest, unsigned size);

// Random bytes from the secure element RNG mixed with A0 noise.
void walletRandom(uint8_t *out, size_t len);

void generateWallet(Adafruit_SSD1306 &display,SecureStorage &eeprom);

// A wallet of this firmware's format is stored (flag and public record).
bool walletPresent(SecureStorage &eeprom);

String getWordsInString(String data, char separator, int index);

// Outcome of a signing request. Every signer shows the request on the
// display, asks for confirmation and the PIN, and only then signs.
enum WalletStatus {
  WALLET_OK = 0,
  WALLET_REJECTED,    // user pressed NO
  WALLET_WRONG_PIN,
  WALLET_INVALID,     // malformed or unsupported input
  WALLET_TOO_LARGE,   // result does not fit the output buffer
  WALLET_SE_ERROR,    // secure element failure / wallet data mismatch
};

// Sign every (P2PKH) input of a raw legacy transaction with the key of
// m/44'/0'/0'/0/0 (testnet: m/44'/1'/...); out = signed tx.
WalletStatus signBtcTx(Adafruit_SSD1306 &display, SecureStorage &eeprom, const uint8_t *raw, size_t len,
                       bool testnet, uint8_t *out, size_t cap, size_t *outLen);

// Ethereum signers use m/44'/60'/0'/0/0. Blind-sign a 32-byte hash;
// sig = r | s | recovery id.
WalletStatus signEthHash(Adafruit_SSD1306 &display, SecureStorage &eeprom, const uint8_t hash[32], uint8_t sig[65]);

// Parse, show and sign an unsigned EIP-155 / EIP-1559 transaction;
// out = signed serialized transaction.
WalletStatus signEthTx(Adafruit_SSD1306 &display, SecureStorage &eeprom, const uint8_t *raw, size_t len,
                       uint8_t sig[65], uint8_t *out, size_t cap, size_t *outLen);

// EIP-191 personal_sign of msg.
WalletStatus signEthMessage(Adafruit_SSD1306 &display, SecureStorage &eeprom, const uint8_t *msg, size_t len,
                            uint8_t sig[65]);

// Review a parsed, checked PSBT (psbtReview() == PSBT_OK) on the device,
// unlock the HD root with the PIN and add signatures.
WalletStatus signPsbt(Adafruit_SSD1306 &display, PSBT &psbt, const HdRecord &rec, bool testnet,
                      const PsbtSummary &sum, uint8_t *signedInputs);

// Two-step confirmation, then the PIN (erase the wallet, PIN and PUK
// stay) or the PUK (factory reset). True if the wallet was erased.
bool eraseDevice(Adafruit_SSD1306 &display, SecureStorage &eeprom);

// Old PIN, PUK, new PIN twice.
WalletStatus changePin(Adafruit_SSD1306 &display);

// FIDO2 master secret from the secure element; false if there is none.
bool loadFidoSecret(uint8_t secret[32]);

// FIDO2 signature counter (secure element, monotonic).
bool fidoCounter(uint32_t &value, bool increment);

// Receive addresses (#0) of the stored wallet. Deriving them takes
// seconds on this MCU, so they are computed on first use and cached
// until the wallet changes (generate / erase).
struct WalletAddresses {
  char btc[96];             // native SegWit
  char btcTest[96];
  char btcLegacy[40];       // P2PKH of m/44'/0'/0'/0/0
  char btcTestLegacy[40];
  char eth[43];             // EIP-55
};
const WalletAddresses &walletAddresses(SecureStorage &eeprom);
void forgetWalletAddresses();

// Checksummed Ethereum address (EIP-55) of a compressed public key.
size_t ethAddressFromPub33(const uint8_t pub[33], char out[43]);

boolean askYesNo(Adafruit_SSD1306 &display);

// Block until a button is pressed (no timeout; on-device flows).
Button waitButton();

// Full-screen text for ms milliseconds.
void showMessage(Adafruit_SSD1306 &display, const char *text, uint32_t ms);

// Enter n hex digits (PIN: SE_PIN_DIGITS, PUK: SE_PUK_DIGITS) with the two
// buttons: NO steps the shown digit, YES accepts it; each digit starts at
// a random value. False on timeout (digits are then incomplete).
bool askPin(Adafruit_SSD1306 &display, uint8_t *digits, int n, const char *title);

#endif
