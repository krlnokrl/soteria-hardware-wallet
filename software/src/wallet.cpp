#include "wallet.h"
#include "bip39.h"
#include "utils.h"
#include "crypto/ethtx.h"
#include "crypto/btchd.h"
#include "buttons.h"

#define HARDENED 0x80000000UL

Atecc gAtecc;
SeWallet gSe;

String getWordsInString(String data, char separator, int index)
{
  int maxIndex = data.length() - 1;
  int j = 0;
  String chunkVal = "";

  for (int i = 0; i <= maxIndex && j <= index; i++)
  {
    chunkVal.concat(data[i]);

    if (data[i] == separator)
    {
      j++;

      if (j > index)
      {
        chunkVal.trim();
        return chunkVal;
      }

      chunkVal = "";
    }
    else if ((i == maxIndex) && (j < index)) {
      chunkVal = "";
      return chunkVal;
    }
  }
  return chunkVal;
}


int RNGpin(uint8_t *dest, unsigned size) {
  while (size) {
    uint32_t rawPool = 0;

    // Accumulate a 32-bit pool of mixed entropy per output byte
    for (unsigned i = 0; i < 32; ++i) {
      // CPU core timing jitter
      uint32_t t1 = SysTick->VAL;

      int init = analogRead(0);
      int red = analogRead(1) & 0x01;
      uint16_t count = 0;

      // Analog change with a safety guard
      while (analogRead(0) == init) {
        ++count;
        if (count > 1024) break;
      }

      // Post-read CPU core timing jitter
      uint32_t timingJitter = t1 ^ SysTick->VAL;

      // Blend noise sources (init, red, count, jitter)
      uint32_t bitSource = (init ^ red ^ count ^ timingJitter) & 0x01;
      rawPool = (rawPool << 1) | bitSource;
    }

    // Whitening / Conditioning
    uint32_t mixed = rawPool ^ (rawPool >> 7) ^ (rawPool >> 14) ^ (rawPool >> 21);
    mixed ^= (mixed >> 4);

    *dest++ = (uint8_t)(mixed & 0xFF);
    --size;
  }
  return 1;
}

void walletRandom(uint8_t *out, size_t len){
  gSe.random(out, len);
}

// uBitcoin's randomness hook (ECDSA blinding); its SAMD fallback is a
// weak PRNG.
extern "C" uint32_t random32(void){
  uint32_t v;
  gSe.random((uint8_t *)&v, sizeof(v));
  return v;
}

/* ------------------------------------------------------------------ */
/* Addresses                                                           */
/* ------------------------------------------------------------------ */

static WalletAddresses s_addresses;
static bool s_addressesValid = false;

static void legacyAddress(const uint8_t pub[33], bool testnet, char *out, size_t cap){
  PublicKey pk(pub);   // parse compressed SEC bytes
  pk.legacyAddress(out, cap, testnet ? &Testnet : &Mainnet);
  out[cap - 1] = 0;
}

const WalletAddresses &walletAddresses(SecureStorage &eeprom){
  if (s_addressesValid) return s_addresses;
  WalletAddresses &a = s_addresses;
  memset(&a, 0, sizeof(a));
  HdRecord hd;
  if (!eeprom.readHd(hd)) return a;
  legacyAddress(hd.btcLegacy, false, a.btcLegacy, sizeof(a.btcLegacy));
  legacyAddress(hd.btcTestLegacy, true, a.btcTestLegacy, sizeof(a.btcTestLegacy));
  ethAddressFromPub33(hd.eth, a.eth);
  hdAddress(hd, false, 0, 0, a.btc, sizeof(a.btc));
  hdAddress(hd, true, 0, 0, a.btcTest, sizeof(a.btcTest));
  s_addressesValid = true;
  return a;
}

void forgetWalletAddresses(){
  s_addressesValid = false;
}

size_t ethAddressFromPub33(const uint8_t pub33[33], char out[43]){
  // Expand to 0x04 || x || y and derive the Ethereum address from it.
  PublicKey pub(pub33);
  pub.compressed = false;
  uint8_t unpk[65];
  pub.sec(unpk, 65);
  return ethAddressFromPubkey(unpk, out);
}

// m/44'/coin'/0'/0/0
static HDPrivateKey bip44Key(const HDPrivateKey &root, uint32_t coin){
  uint32_t path[5] = { HARDENED | 44, HARDENED | coin, HARDENED, 0, 0 };
  return root.derive(path, 5);
}

/* ------------------------------------------------------------------ */
/* Prompts                                                             */
/* ------------------------------------------------------------------ */

Button waitButton(){
  buttonsArm();
  for (;;) {
    Button b = buttonsPoll();
    if (b != BTN_NONE) return b;
    delay(5);
  }
}

void showMessage(Adafruit_SSD1306 &display, const char *text, uint32_t ms){
  display.clearDisplay();
  display.setTextColor(WHITE);
  display.setTextSize(1);
  display.setCursor(0, 0);
  display.println(text);
  display.display();
  delay(ms);
}

static void showWrongPin(Adafruit_SSD1306 &display){
  showMessage(display, "Wrong PIN!", 2000);
}

static uint32_t s_promptTimeout = 0;
static bool s_promptTimedOut = false;

void setPromptTimeout(uint32_t ms){
  s_promptTimeout = ms;
  s_promptTimedOut = false;   // don't report a stale timeout for the next request
}

bool promptTimedOut(){
  return s_promptTimedOut;
}

// True (after telling the user) once a prompt started at `start` expired.
static bool promptExpired(Adafruit_SSD1306 &display, uint32_t start){
  if (s_promptTimeout == 0 || millis() - start < s_promptTimeout) return false;
  s_promptTimedOut = true;
  display.clearDisplay();
  display.setCursor(0, 0);
  display.setTextSize(1);
  display.setTextColor(WHITE);
  display.println("Timed out.");
  display.println("Request cancelled.");
  display.display();
  delay(1500);
  return true;
}

static void drawDigits(Adafruit_SSD1306 &display, const char *title, const uint8_t *digits,
                       int n, int current){
  display.clearDisplay();
  display.setTextColor(WHITE);
  display.setTextSize(1);
  display.setCursor(0, 0);
  display.print(title);
  if (current < n) {
    display.print(" ");
    display.print(current + 1);
    display.print("/");
    display.print(n);
  }
  display.setTextSize(2);   // 12 px per char
  display.setCursor((display.width() - 12 * n) / 2, 22);
  for (int v = 0; v < n; v++) {
    if (v == current) display.print(digits[v], HEX);
    else display.print(v < current ? "*" : "-");
  }
  display.setTextSize(1);
  display.setCursor(0, 44);
  display.print(current < n ? "NO: next value" : "Use these digits?");
  displayYesNo(display);
  display.display();
}

bool askPin(Adafruit_SSD1306 &display, uint8_t *digits, int n, const char *title){
  s_promptTimedOut = false;
  for (;;) {
    for (int i = 0; i < n; i++) {
      uint8_t start;
      walletRandom(&start, 1);
      digits[i] = start & 0x0F;   // random start: presses reveal nothing
      buttonsArm();
      uint32_t t0 = millis();     // each digit gets the full timeout
      drawDigits(display, title, digits, n, i);
      for (;;) {
        if (promptExpired(display, t0)) return false;
        Button b = buttonsPoll();
        if (b == BTN_YES) break;
        if (b == BTN_NO) {
          digits[i] = (digits[i] + 1) & 0x0F;
          drawDigits(display, title, digits, n, i);
        }
        delay(5);
      }
    }
    drawDigits(display, title, digits, n, n);
    buttonsArm();
    uint32_t t0 = millis();
    for (;;) {
      if (promptExpired(display, t0)) return false;
      Button b = buttonsPoll();
      if (b == BTN_YES) return true;
      if (b == BTN_NO) break;     // enter all digits again
      delay(5);
    }
  }
}

boolean askYesNo(Adafruit_SSD1306 &display){
  s_promptTimedOut = false;
  displayYesNo(display);
  display.display();
  display.clearDisplay();
  display.setCursor(0, 0);
  buttonsArm();
  uint32_t start = millis();
  for (;;) {
    Button b = buttonsPoll();
    if (b == BTN_NO) return false;
    if (b == BTN_YES) return true;
    if (promptExpired(display, start)) return false;
    delay(5);
  }
}

static void showSeError(Adafruit_SSD1306 &display, SeResult r){
  char msg[64];
  snprintf(msg, sizeof(msg), "Failed:\n%s", seResultText(r));
  showMessage(display, msg, 2500);
}

/* ------------------------------------------------------------------ */
/* Wallet creation                                                     */
/* ------------------------------------------------------------------ */

// Show the PUK until YES; it is needed for PIN changes and factory reset.
static void showPuk(Adafruit_SSD1306 &display, const uint8_t puk[SE_PUK_DIGITS]){
  for (;;) {
    display.clearDisplay();
    display.setTextColor(WHITE);
    display.setTextSize(1);
    display.setCursor(0, 0);
    display.println("Write down the PUK");
    display.println("(with the 12 words):");
    display.setTextSize(2);
    display.setCursor(10, 26);
    for (int i = 0; i < SE_PUK_DIGITS; i++) {
      if (i == 4) display.print(' ');
      display.print(puk[i], HEX);
    }
    displayYesNo(display);
    display.display();
    if (waitButton() == BTN_YES) return;
  }
}

void generateWallet(Adafruit_SSD1306 &display,SecureStorage &eeprom)
{
  if (!gSe.ready()) {
    showSeError(display, SE_NOT_READY);
    return;
  }
  uint8_t pin[SE_PIN_DIGITS];
  uint8_t pin1[SE_PIN_DIGITS];
  uint8_t seed[32];

  if (!askPin(display, pin, SE_PIN_DIGITS, "New PIN")) return;
  if (!askPin(display, pin1, SE_PIN_DIGITS, "Repeat PIN")) return;
  if (memcmp(pin, pin1, sizeof(pin)) != 0) {
    showMessage(display, "PINs do not match!", 2000);
    return;
  }
  display.clearDisplay();
  displaySandglass(display);
  displayProgressBar(display);
  display.display();

  // Entropy: secure element RNG mixed with A0 noise
  if (!gSe.random(seed, sizeof(seed))) {
    showMessage(display, "Secure element RNG\nfailed.", 2500);
    return;
  }
  display.setTextSize(1);
  display.setCursor(0, 0);
  updateProgressBar(display,5);
  display.display();

  HDPrivateKey hdKey;
  String s = seedToWords(seed, 16);
  memset(seed, 0, sizeof(seed));
  // seedToWords() leaves a trailing space; BIP39 hashes the mnemonic
  // verbatim, so it must go or the 12 words restore a different wallet.
  s.trim();
  char mnem[200];
  s.toCharArray(mnem, sizeof(mnem));
  updateProgressBar(display,20);
  display.display();
  const char *pass = "";
  hdKey.fromMnemonic(mnem, strlen(mnem), pass, 0);
  memset(mnem, 0, sizeof(mnem));
  updateProgressBar(display,40);
  display.display();

  // Public data for the EEPROM: BIP84 xpubs, BIP44 legacy and ETH keys
  HdRecord hd;
  hdMakeRecord(hdKey, hd);
  bip44Key(hdKey, 0).publicKey().sec(hd.btcLegacy, sizeof(hd.btcLegacy));
  bip44Key(hdKey, 1).publicKey().sec(hd.btcTestLegacy, sizeof(hd.btcTestLegacy));
  bip44Key(hdKey, 60).publicKey().sec(hd.eth, sizeof(hd.eth));
  updateProgressBar(display,60);
  display.display();

  // FIDO2 master secret = HMAC(m/44'/99'/0'/0/0). Readable without the
  // PIN (a security key must work without it); one-way, so it exposes no
  // wallet key. Derived from the seed, so the 12 words restore it.
  uint8_t u2fPriv[32], fido[32], root[SE_ROOT_SIZE];
  bip44Key(hdKey, 99).getSecret(u2fPriv);
  const char fidoLabel[] = "Soteria FIDO2";
  sha256Hmac((const uint8_t *)fidoLabel, strlen(fidoLabel), u2fPriv, sizeof(u2fPriv), fido);
  memset(u2fPriv, 0, sizeof(u2fPriv));
  hdRootBytes(hdKey, root);
  updateProgressBar(display,70);
  display.display();

  // Seal everything in the secure element. A chip that still holds the
  // PUK of an erased wallet needs it.
  uint8_t puk[SE_PUK_DIGITS], oldPuk[SE_PUK_DIGITS];
  SeResult r = gSe.create(pin, root, fido, nullptr, puk);
  while (r == SE_NEED_PUK || r == SE_WRONG_PUK) {
    showMessage(display, r == SE_NEED_PUK ? "The secure element\nholds a PUK: enter\nthe PUK of the old\nwallet."
                                          : "Wrong PUK!", 2500);
    if (!askPin(display, oldPuk, SE_PUK_DIGITS, "Old PUK")) break;
    display.clearDisplay();
    displaySandglass(display);
    display.display();
    r = gSe.create(pin, root, fido, oldPuk, puk);
  }
  memset(root, 0, sizeof(root));
  memset(fido, 0, sizeof(fido));
  memset(pin, 0, sizeof(pin));
  memset(pin1, 0, sizeof(pin1));
  memset(oldPuk, 0, sizeof(oldPuk));
  if (r != SE_OK) {
    showSeError(display, r);
    return;
  }
  eeprom.eraseLegacyKeys();
  eeprom.writeHd(hd);
  updateProgressBar(display,100);
  display.display();

  // Show the 12 words twice: once to write them down, once to check the
  // copy. YES = next word, NO = previous word.
  for (int step = 0; step < 24; ) {
    int i = step % 12;
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(WHITE);
    display.setCursor(0, 0);
    display.print(step < 12 ? "Write down word " : "Check word ");
    display.print(i + 1);
    display.print("/12");
    String word = getWordsInString(s, ' ', i);
    word.trim();
    display.setTextSize(2);   // 12 px per char, <= 8 letters
    display.setCursor((display.width() - 12 * (int)word.length()) / 2, 24);
    display.print(word);
    displayYesNo(display);
    display.display();
    if (waitButton() == BTN_YES) step++;
    else if (step > 0) step--;
  }
  showPuk(display, puk);
  memset(puk, 0, sizeof(puk));

  uint16_t flag = GEN_FLAG;
  eeprom.writeFlag((unsigned char)6, flag);
  forgetWalletAddresses();
}

bool walletPresent(SecureStorage &eeprom){
  HdRecord hd;
  return eeprom.readFlag(6) == GEN_FLAG && eeprom.readHd(hd);
}

bool loadFidoSecret(uint8_t secret[32]){
  return gSe.fidoSecret(secret);
}

bool fidoCounter(uint32_t &value, bool increment){
  return gSe.fidoCounter(value, increment);
}

/* ------------------------------------------------------------------ */
/* Unlocking                                                           */
/* ------------------------------------------------------------------ */

// Ask for the PIN; the secure element checks it and releases the root.
static WalletStatus unlockRoot(Adafruit_SSD1306 &display, const HdRecord &rec, HDPrivateKey &root){
  uint8_t pin[SE_PIN_DIGITS];
  if (!askPin(display, pin, SE_PIN_DIGITS, "PIN")) return WALLET_REJECTED;
  showMessage(display, "Checking PIN...", 0);
  uint8_t raw[SE_ROOT_SIZE];
  uint32_t failed = 0;
  SeResult r = gSe.unlock(pin, raw, &failed);
  memset(pin, 0, sizeof(pin));
  if (r == SE_WRONG_PIN) {
    showWrongPin(display);
    return WALLET_WRONG_PIN;
  }
  if (r != SE_OK) {
    showSeError(display, r);
    return WALLET_SE_ERROR;
  }
  bool ours = hdRootFromBytes(raw, rec, root);
  memset(raw, 0, sizeof(raw));
  if (!ours) {
    showMessage(display, "Wallet data does not\nmatch the secure\nelement.", 2500);
    return WALLET_SE_ERROR;
  }
  if (failed) {
    char msg[64];
    snprintf(msg, sizeof(msg), "WARNING:\n%lu wrong PIN\nattempt(s) since the\nlast unlock!", (unsigned long)failed);
    showMessage(display, msg, 3000);
  }
  return WALLET_OK;
}

// PIN, then the BIP44 key m/44'/coin'/0'/0/0.
static WalletStatus unlockCoinKey(Adafruit_SSD1306 &display, SecureStorage &eeprom, uint32_t coin,
                                  PrivateKey &key){
  HdRecord rec;
  if (!eeprom.readHd(rec)) return WALLET_SE_ERROR;
  HDPrivateKey root;
  WalletStatus st = unlockRoot(display, rec, root);
  if (st != WALLET_OK) return st;
  showMessage(display, "Signing...", 0);
  HDPrivateKey child = bip44Key(root, coin);
  uint8_t secret[32];
  child.getSecret(secret);
  key = PrivateKey(secret, true, coin == 1 ? &Testnet : &Mainnet);
  memset(secret, 0, sizeof(secret));
  return WALLET_OK;
}

// ECDSA secp256k1 (RFC 6979) over hash; sig = r(32) | s(32) | recovery id
static void signHash(const PrivateKey &pk, const uint8_t hash[32], uint8_t sig[65]){
  pk.sign(hash).bin(sig, 65);
}

static void beginScreen(Adafruit_SSD1306 &display, const char *title){
  display.clearDisplay();
  display.setCursor(0, 0);
  display.setTextSize(1);
  display.setTextColor(WHITE);
  display.println(title);
}

static void showSigned(Adafruit_SSD1306 &display){
  beginScreen(display, "Signed.");
  display.display();
  delay(800);
}

// Exact BTC amount from satoshis ("0.00012345"); floats would round.
static void printBtc(Adafruit_SSD1306 &display, uint64_t sats){
  char buf[24];
  snprintf(buf, sizeof(buf), "%lu.%08lu", (unsigned long)(sats / 100000000ULL),
           (unsigned long)(sats % 100000000ULL));
  display.print(buf);
}

// Label line, then the EIP-55 address on exactly two 21-char lines.
static void printEthAddr(Adafruit_SSD1306 &display, const char *label, const uint8_t addr[20]){
  char buf[43];
  display.println(label);
  ethAddressToString(addr, buf);
  display.println(buf);
}

WalletStatus signBtcTx(Adafruit_SSD1306 &display, SecureStorage &eeprom, const uint8_t *raw, size_t len,
                       bool testnet, uint8_t *out, size_t cap, size_t *outLen){
  Tx tx;
  // uBitcoin's parsers are not safe on malformed input: check structure first
  if (!btcTxWellFormed(raw, len)) return WALLET_INVALID;
  if (tx.parse(raw, len) != len || tx.inputsNumber == 0) return WALLET_INVALID;

  // One screen per output: the full address must be checkable.
  uint64_t total = 0;
  for (int i = 0; i < tx.outputsNumber; i++) {
    char title[24];
    snprintf(title, sizeof(title), "BTC output %d/%d", i + 1, (int)tx.outputsNumber);
    beginScreen(display, title);
    String addr = tx.txOuts[i].address(testnet ? &Testnet : &Mainnet);
    display.println(addr.length() ? addr : String("(non-standard script)"));
    printBtc(display, tx.txOuts[i].amount);
    display.println(" BTC");
    display.display();
    if (!askYesNo(display)) return WALLET_REJECTED;
    total += tx.txOuts[i].amount;
  }

  // Legacy transactions do not commit to input amounts, so the fee is unknown.
  beginScreen(display, "Sign BTC tx?");
  display.print(tx.inputsNumber); display.println(" input(s)");
  display.print("Total out: "); printBtc(display, total); display.println();
  display.println("Fee: unknown");
  display.display();
  if (!askYesNo(display)) return WALLET_REJECTED;

  PrivateKey pk;
  WalletStatus st = unlockCoinKey(display, eeprom, testnet ? 1 : 0, pk);
  if (st != WALLET_OK) return st;
  for(int i=0; i<tx.inputsNumber; i++){
    // signInput() sets scriptSig to <sig> <pubkey> (P2PKH)
    tx.signInput(i, pk);
  }
  if (tx.length() > cap) return WALLET_TOO_LARGE;
  *outLen = tx.serialize(out, cap);
  showSigned(display);
  return WALLET_OK;
}

WalletStatus signEthHash(Adafruit_SSD1306 &display, SecureStorage &eeprom, const uint8_t hash[32], uint8_t sig[65]){
  // Blind signing: nothing but the hash can be shown, so show all of it.
  beginScreen(display, "Sign ETH hash? BLIND");
  display.println(toHex(hash, 32));
  display.display();
  if (!askYesNo(display)) return WALLET_REJECTED;

  PrivateKey pk;
  WalletStatus st = unlockCoinKey(display, eeprom, 60, pk);
  if (st != WALLET_OK) return st;
  signHash(pk, hash, sig);
  showSigned(display);
  return WALLET_OK;
}

WalletStatus signEthTx(Adafruit_SSD1306 &display, SecureStorage &eeprom, const uint8_t *raw, size_t len,
                       uint8_t sig[65], uint8_t *out, size_t cap, size_t *outLen){
  EthTx tx;
  if (!ethTxParse(raw, len, tx)) return WALLET_INVALID;
  uint8_t fee[32];
  if (!ethTxMaxFee(tx, fee)) return WALLET_INVALID;
  char buf[84];

  // Chain name and native coin from the table; unknown chains by id.
  const EthChain *chain = ethChainLookup(tx.chainId);
  const char *sym = chain ? chain->symbol : "(native)";
  char title[22];
  if (chain) {
    snprintf(title, sizeof(title), "%s", chain->name);
  } else {
    uint8_t chainBe[8];
    for (int i = 0; i < 8; i++) chainBe[i] = (uint8_t)(tx.chainId >> (56 - 8 * i));
    ethFormatUnits(chainBe, 8, 0, buf, sizeof(buf));
    snprintf(title, sizeof(title), "Chain %s", buf);
  }
  bool hasValue = false;
  for (int i = 0; i < tx.valueLen; i++) hasValue |= tx.value[i] != 0;
  ethFormatUnits(tx.value, tx.valueLen, 18, buf, sizeof(buf));
  String value = String(buf) + " " + sym;

  Erc20Call call;
  if (ethDecodeErc20(tx, call)) {
    // Calldata has the shape of an ERC-20 call; amounts are in the
    // token's base units (decimals are unknown to the device).
    beginScreen(display, title);
    display.println(call.kind == ERC20_APPROVE ? "TOKEN APPROVAL" : "ERC-20 token transfer");
    printEthAddr(display, "Token contract:", tx.to);
    if (hasValue) display.println("+ " + value);
    display.display();
    if (!askYesNo(display)) return WALLET_REJECTED;

    if (call.kind == ERC20_TRANSFER_FROM) {
      beginScreen(display, "Token transfer");
      printEthAddr(display, "From:", call.from);
      display.display();
      if (!askYesNo(display)) return WALLET_REJECTED;
    }
    beginScreen(display, call.kind == ERC20_APPROVE ? "Allow spender" : "Token transfer");
    printEthAddr(display, call.kind == ERC20_APPROVE ? "Spender:" : "To:", call.to);
    if (call.kind == ERC20_APPROVE && ethIsMaxUint256(call.amount)) {
      display.println("Amount: UNLIMITED!");
    } else {
      ethFormatUnits(call.amount, 32, 0, buf, sizeof(buf));
      display.println("Amount (base units):");
      display.println(buf);
    }
    display.display();
    if (!askYesNo(display)) return WALLET_REJECTED;
  } else {
    beginScreen(display, title);
    if (tx.dataLen) display.println("CONTRACT CALL");
    if (tx.to) printEthAddr(display, tx.dataLen ? "Contract:" : "To:", tx.to);
    else display.println("Deploy new contract");
    display.println("Value:");
    display.println(value);
    display.display();
    if (!askYesNo(display)) return WALLET_REJECTED;
  }

  // Fee screen
  beginScreen(display, tx.type == 2 ? "Fee (EIP-1559)" : "Fee (legacy)");
  display.println("Max fee:");
  ethFormatUnits(fee, 32, 18, buf, sizeof(buf));
  display.print(buf);
  display.print(" ");
  display.println(sym);
  if (tx.dataLen) {
    display.print("Data: ");
    display.print((unsigned long)tx.dataLen);
    display.println(" bytes");
  }
  display.display();
  if (!askYesNo(display)) return WALLET_REJECTED;

  PrivateKey pk;
  WalletStatus st = unlockCoinKey(display, eeprom, 60, pk);
  if (st != WALLET_OK) return st;
  uint8_t hash[32];
  keccak256(raw, len, hash);   // both formats sign keccak256(unsigned bytes)
  signHash(pk, hash, sig);
  *outLen = ethTxEncodeSigned(tx, sig, out, cap);
  if (*outLen == 0) return WALLET_TOO_LARGE;
  showSigned(display);
  return WALLET_OK;
}

WalletStatus signEthMessage(Adafruit_SSD1306 &display, SecureStorage &eeprom, const uint8_t *msg, size_t len,
                            uint8_t sig[65]){
  beginScreen(display, "Sign ETH message?");
  for (size_t i = 0; i < len && i < 100; i++) {
    uint8_t c = msg[i];
    display.print((c >= 32 && c < 127) ? (char)c : '.');
  }
  if (len > 100) display.print("...");
  display.display();
  if (!askYesNo(display)) return WALLET_REJECTED;

  PrivateKey pk;
  WalletStatus st = unlockCoinKey(display, eeprom, 60, pk);
  if (st != WALLET_OK) return st;
  uint8_t hash[32];
  ethPersonalMessageHash(msg, len, hash);
  signHash(pk, hash, sig);
  showSigned(display);
  return WALLET_OK;
}

WalletStatus signPsbt(Adafruit_SSD1306 &display, PSBT &psbt, const HdRecord &rec, bool testnet,
                      const PsbtSummary &sum, uint8_t *signedInputs){
  const char *unit = testnet ? " tBTC" : " BTC";

  // One screen per payment: every address must be checkable. Outputs
  // that provably return to this wallet (change) are only totalled.
  int payments = 0, shown = 0;
  for (size_t i = 0; i < psbt.tx.outputsNumber; i++) {
    if (!((sum.ownOutputs >> i) & 1)) payments++;
  }
  char addr[96];
  for (size_t i = 0; i < psbt.tx.outputsNumber; i++) {
    if ((sum.ownOutputs >> i) & 1) continue;
    const TxOut &out = psbt.tx.txOuts[i];
    char title[22];
    snprintf(title, sizeof(title), "Send %d/%d", ++shown, payments);
    beginScreen(display, title);
    if (btcScriptAddress(out.scriptPubkey, testnet, addr, sizeof(addr))) display.println(addr);
    else display.println("OP_RETURN (data)");
    printBtc(display, out.amount);
    display.println(unit);
    display.display();
    if (!askYesNo(display)) return WALLET_REJECTED;
  }

  beginScreen(display, testnet ? "Confirm TESTNET tx" : "Confirm transaction");
  display.print("Send:   "); printBtc(display, sum.sendTotal); display.println();
  display.print("Fee:    "); printBtc(display, sum.fee); display.println();
  if (sum.ownTotal) {
    display.print("Change: "); printBtc(display, sum.ownTotal); display.println();
  }
  uint64_t moved = sum.sendTotal ? sum.sendTotal : sum.ownTotal;
  if (sum.fee * 10 > moved) display.println("WARNING: fee > 10%!");
  display.display();
  if (!askYesNo(display)) return WALLET_REJECTED;

  HDPrivateKey root;
  WalletStatus st = unlockRoot(display, rec, root);
  if (st != WALLET_OK) return st;
  showMessage(display, "Signing...", 0);
  *signedInputs = psbtSign(psbt, root);
  if (*signedInputs == 0) return WALLET_INVALID;
  showSigned(display);
  return WALLET_OK;
}

bool eraseDevice(Adafruit_SSD1306 &display, SecureStorage &eeprom){
  display.clearDisplay();
  display.setCursor(0, 0);
  display.setTextSize(2);
  display.println("!!ERASE!!");
  display.setTextSize(1);
  display.println("\nAll keys will be lost forever!");
  display.display();
  delay(2000);
  if (!askYesNo(display)) return false;
  display.setTextSize(1);
  display.println("Are you sure you want to erase?");
  display.display();
  if (!askYesNo(display)) return false;

  // PIN: erase the wallet (PIN and PUK stay). PUK: factory reset (also
  // for a forgotten PIN).
  display.println("Authorise with:");
  display.println();
  display.println("YES: PIN");
  display.println("NO:  PUK (forgot PIN,");
  display.println("     factory reset)");
  bool withPin = askYesNo(display);
  if (promptTimedOut()) return false;
  SeResult r;
  if (withPin) {
    uint8_t pin[SE_PIN_DIGITS];
    if (!askPin(display, pin, SE_PIN_DIGITS, "PIN")) return false;
    showMessage(display, "Erasing...", 0);
    r = gSe.wipe(pin);
    memset(pin, 0, sizeof(pin));
  } else {
    uint8_t puk[SE_PUK_DIGITS];
    if (!askPin(display, puk, SE_PUK_DIGITS, "PUK")) return false;
    showMessage(display, "Factory reset...", 0);
    r = gSe.factoryReset(puk);
    memset(puk, 0, sizeof(puk));
  }
  if (r != SE_OK) {
    showSeError(display, r);
    return false;
  }

  uint16_t flag = 0xFFFF;
  eeprom.writeFlag(6, flag);
  eeprom.writeName(6, "");
  eeprom.eraseHd();
  eeprom.eraseLegacyKeys();
  forgetWalletAddresses();
  showMessage(display, "DONE!", 1000);
  return true;
}

WalletStatus changePin(Adafruit_SSD1306 &display){
  display.clearDisplay();
  display.setCursor(0, 0);
  display.setTextSize(1);
  display.setTextColor(WHITE);
  display.println("Change the PIN?");
  display.println();
  display.println("Needs the current PIN");
  display.println("and the PUK.");
  if (!askYesNo(display)) return WALLET_REJECTED;
  uint8_t oldPin[SE_PIN_DIGITS], puk[SE_PUK_DIGITS], pin[SE_PIN_DIGITS], pin1[SE_PIN_DIGITS];
  WalletStatus st = WALLET_REJECTED;
  if (askPin(display, oldPin, SE_PIN_DIGITS, "Current PIN") &&
      askPin(display, puk, SE_PUK_DIGITS, "PUK") &&
      askPin(display, pin, SE_PIN_DIGITS, "New PIN") &&
      askPin(display, pin1, SE_PIN_DIGITS, "Repeat PIN")) {
    if (memcmp(pin, pin1, sizeof(pin)) != 0) {
      showMessage(display, "PINs do not match!", 2000);
    } else {
      showMessage(display, "Changing PIN...", 0);
      SeResult r = gSe.changePin(oldPin, puk, pin);
      if (r == SE_OK) {
        showMessage(display, "PIN changed.", 1500);
        st = WALLET_OK;
      } else {
        showSeError(display, r);
        st = r == SE_WRONG_PIN ? WALLET_WRONG_PIN : r == SE_WRONG_PUK ? WALLET_REJECTED : WALLET_SE_ERROR;
      }
    }
  }
  memset(oldPin, 0, sizeof(oldPin));
  memset(puk, 0, sizeof(puk));
  memset(pin, 0, sizeof(pin));
  memset(pin1, 0, sizeof(pin1));
  return st;
}
