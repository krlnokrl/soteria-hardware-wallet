#include "wallet.h"
#include "bip39.h"
#include "utils.h"
#include "crypto/ethtx.h"
#include "crypto/btchd.h"
#include "buttons.h"

// Placeholder: this board revision has no PIN potentiometer wired to an
// analog input, so every PIN digit reads as 7 (PIN = 77777).
#define PIN_PLACEHOLDER_DIGIT 7

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
        if (count > 4096) break; 
      }

      // Post-read CPU core timing jitter
      uint32_t t2 = SysTick->VAL;
      uint32_t timingJitter = t1 ^ t2;

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

static WalletAddresses s_addresses;
static bool s_addressesValid = false;

const WalletAddresses &walletAddresses(SecureStorage &eeprom){
  if (s_addressesValid) return s_addresses;
  WalletAddresses &a = s_addresses;
  memset(&a, 0, sizeof(a));
  Key btc, eth, btct;
  eeprom.getKey(0, btc);
  eeprom.getKey(1, eth);
  eeprom.getKey(2, btct);
  keyAddress(btc, false).toCharArray(a.btcLegacy, sizeof(a.btcLegacy));
  keyAddress(btct, true).toCharArray(a.btcTestLegacy, sizeof(a.btcTestLegacy));
  ethAddressFromKey(eth, a.eth);
  HdRecord hd;
  a.segwit = eeprom.readHd(hd);
  if (a.segwit) {
    hdAddress(hd, false, 0, 0, a.btc, sizeof(a.btc));
    hdAddress(hd, true, 0, 0, a.btcTest, sizeof(a.btcTest));
  }
  s_addressesValid = true;
  return a;
}

void forgetWalletAddresses(){
  s_addressesValid = false;
}

size_t ethAddressFromKey(const Key &k, char out[43]){
  // The private key is PIN-encrypted, so expand the stored compressed
  // public key to 0x04 || x || y and derive the Ethereum address from it.
  PublicKey pub(k.publicKey.data());
  pub.compressed = false;                 // uncompressed for Ethereum
  uint8_t unpk[65];
  pub.sec(unpk, 65);
  return ethAddressFromPubkey(unpk, out);
}

String keyAddress(const Key &k, bool testnet){
  if (k.network == ETH){
    char addr[43];
    ethAddressFromKey(k, addr);
    return String(addr);
  }
  PublicKey pk(k.publicKey.data());   // parse compressed SEC bytes
  char buf[64];
  pk.legacyAddress(buf, sizeof(buf), testnet ? &Testnet : &Mainnet);
  buf[sizeof(buf)-1] = 0;
  return String(buf);
}

void generateWallet(Adafruit_SSD1306 &display,SecureStorage &eeprom)
{
  uint8_t pin[5];
  uint8_t pin1[5];
  uint8_t seed[32];

  if (!askPin(display, pin)) return;
  showMessage(display, "Enter the same PIN\nagain to confirm.", 1500);
  if (!askPin(display, pin1)) return;
  if (memcmp(pin, pin1, sizeof(pin)) != 0) {
    showMessage(display, "PINs do not match!", 2000);
    return;
  }
  display.clearDisplay();
  displaySandglass(display);
  displayProgressBar(display);
  display.display();

  RNGpin(seed, 32);
  sha256(seed, 32, seed);
  display.setTextSize(1);
  display.setCursor(0, 0);
  updateProgressBar(display,5);
  display.display();

  HDPrivateKey hdKey;
  String s = seedToWords(seed, 16);
  // seedToWords() leaves a trailing space; BIP39 hashes the mnemonic
  // verbatim, so it must go or the 12 words restore a different wallet.
  s.trim();
  char mnem[200];
  s.toCharArray(mnem, sizeof(mnem));
  updateProgressBar(display,30);
  display.display();
  const char *pass = "";
  hdKey.fromMnemonic(mnem, strlen(mnem), pass, 0);
  updateProgressBar(display,40);
  display.display();

  // BIP32 root for SegWit (BIP84) accounts and PSBT signing
  HdRecord hd;
  hdMakeRecord(hdKey, pin, hd);
  eeprom.writeHd(hd);
  updateProgressBar(display,50);
  display.display();

  HDPrivateKey btcKey  = hdKey.hardenedChild(44).hardenedChild(0).hardenedChild(0).child(0).child(0);
  HDPrivateKey btctKey = hdKey.hardenedChild(44).hardenedChild(1).hardenedChild(0).child(0).child(0);
  HDPrivateKey ethKey  = hdKey.hardenedChild(44).hardenedChild(60).hardenedChild(0).child(0).child(0);
  HDPrivateKey u2fKey  = hdKey.hardenedChild(44).hardenedChild(99).hardenedChild(0).child(0).child(0);
  updateProgressBar(display,60);
  display.display();

  Key k;

  // BTC  m/44'/0'/0'/0/0
  k.network = BTC;
  k.id = 0;
  k.nonce = 0;
  btcKey.getSecret(k.privateKey.data());
  btcKey.publicKey().sec(k.publicKey.data(), k.publicKey.size());
  xorKey(k, pin);
  eeprom.storeKey(0, k);
  updateProgressBar(display,70);
  display.display();

  // BTC testnet  m/44'/1'/0'/0/0
  k.network = BTC;
  k.id = 2;
  k.nonce = 0;
  btctKey.getSecret(k.privateKey.data());
  btctKey.publicKey().sec(k.publicKey.data(), k.publicKey.size());
  xorKey(k, pin);
  eeprom.storeKey(2, k);
  updateProgressBar(display,80);
  display.display();

  // U2F  m/44'/99'/0'/0/0
  k.network = U2F;
  k.id = 3;
  k.nonce = 0;
  u2fKey.getSecret(k.privateKey.data());
  u2fKey.publicKey().sec(k.publicKey.data(), k.publicKey.size());

  // FIDO2 master secret = HMAC(u2f key). Kept in clear so the security key
  // works without the PIN; one-way, so leaking it exposes no wallet key.
  Key fido;
  fido.network = U2F;
  fido.id = FIDO_KEY_SLOT;
  fido.publicKey.fill(0);
  const char fidoLabel[] = "Soteria FIDO2";
  sha256Hmac((const uint8_t *)fidoLabel, strlen(fidoLabel),
             k.privateKey.data(), k.privateKey.size(), fido.privateKey.data());
  eeprom.storeKey(FIDO_KEY_SLOT, fido);

  xorKey(k, pin);
  eeprom.storeKey(3, k);
  updateProgressBar(display,90);
  display.display();

  // ETH  m/44'/60'/0'/0/0
  k.network = ETH;
  k.id = 1;
  k.nonce = 0;
  ethKey.getSecret(k.privateKey.data());
  ethKey.publicKey().sec(k.publicKey.data(), k.publicKey.size());
  xorKey(k, pin);
  eeprom.storeKey(1, k);
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

  uint16_t flag = GEN_FLAG;
  eeprom.writeFlag((unsigned char)6, flag);
  forgetWalletAddresses();
}

void xorKey(Key &k, uint8_t *pin){
  uint8_t hash[32];
  sha256(pin, 5, hash);
  for(int i=0; i<32;i++)
  {
    k.privateKey[i] = k.privateKey[i] ^ hash[i];
  }
}

bool unlockKey(Key &k, uint8_t *pin){
  xorKey(k, pin);
  PrivateKey pk(k.privateKey.data(), true, &Mainnet);
  uint8_t sec[33];
  pk.publicKey().sec(sec, sizeof(sec));
  return memcmp(sec, k.publicKey.data(), sizeof(sec)) == 0;
}

bool loadFidoSecret(SecureStorage &eeprom, uint8_t secret[32]){
  Key k;
  eeprom.getKey(FIDO_KEY_SLOT, k);
  // Erased / never-written slots read back as 0xFF and fail this check.
  if (k.network != U2F || k.id != FIDO_KEY_SLOT) return false;
  memcpy(secret, k.privateKey.data(), 32);
  return true;
}

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

bool askPin(Adafruit_SSD1306 &display, uint8_t *pin){
  s_promptTimedOut = false;
  for (int i = 0; i < 5; i++) {
    buttonsArm();
    uint32_t start = millis();   // each digit gets the full timeout
    int shown = -1;
    for (;;) {
      if (promptExpired(display, start)) return false;
      int num = PIN_PLACEHOLDER_DIGIT;
      if (num != shown) {        // redraw only when the digit changes
        shown = num;
        display.clearDisplay();
        display.setTextColor(WHITE);
        display.setTextSize(1);
        display.setCursor(0, 0);
        display.print("Enter PIN digit ");
        display.print(i + 1);
        display.print("/5");
        display.setTextSize(3);  // 5 chars x 18 px, centred
        display.setCursor(19, 22);
        for (int v = 0; v < 5; v++) {
          if (v == i) display.print(num, HEX);
          else display.print("*");
        }
        displayYesNo(display);
        display.display();
      }
      Button b = buttonsPoll();
      if (b == BTN_NO) return false;
      if (b == BTN_YES) {
        pin[i] = (uint8_t)shown;
        break;
      }
      delay(10);
    }
  }
  return true;
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

// Ask for the PIN and decrypt k with it.
static WalletStatus unlockWithPin(Adafruit_SSD1306 &display, Key &k){
  uint8_t pin[5];
  if (!askPin(display, pin)) return WALLET_REJECTED;
  if (!unlockKey(k, pin)) {
    showWrongPin(display);
    return WALLET_WRONG_PIN;
  }
  return WALLET_OK;
}

// ECDSA secp256k1 (RFC 6979) over hash; sig = r(32) | s(32) | recovery id
static void signHash(const Key &k, const uint8_t hash[32], uint8_t sig[65]){
  PrivateKey pk(k.privateKey.data(), true, &Mainnet);
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

WalletStatus signBtcTx(Adafruit_SSD1306 &display, const uint8_t *raw, size_t len, Key k,
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

  WalletStatus st = unlockWithPin(display, k);
  if (st != WALLET_OK) return st;
  PrivateKey pk(k.privateKey.data(), true, testnet ? &Testnet : &Mainnet);
  for(int i=0; i<tx.inputsNumber; i++){
    // signInput() sets scriptSig to <sig> <pubkey> (P2PKH)
    tx.signInput(i, pk);
  }
  if (tx.length() > cap) return WALLET_TOO_LARGE;
  *outLen = tx.serialize(out, cap);
  showSigned(display);
  return WALLET_OK;
}

WalletStatus signEthHash(Adafruit_SSD1306 &display, const uint8_t hash[32], Key k, uint8_t sig[65]){
  // Blind signing: nothing but the hash can be shown, so show all of it.
  beginScreen(display, "Sign ETH hash? BLIND");
  display.println(toHex(hash, 32));
  display.display();
  if (!askYesNo(display)) return WALLET_REJECTED;

  WalletStatus st = unlockWithPin(display, k);
  if (st != WALLET_OK) return st;
  signHash(k, hash, sig);
  showSigned(display);
  return WALLET_OK;
}

WalletStatus signEthTx(Adafruit_SSD1306 &display, const uint8_t *raw, size_t len, Key k,
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

  WalletStatus st = unlockWithPin(display, k);
  if (st != WALLET_OK) return st;
  uint8_t hash[32];
  keccak256(raw, len, hash);   // both formats sign keccak256(unsigned bytes)
  signHash(k, hash, sig);
  *outLen = ethTxEncodeSigned(tx, sig, out, cap);
  if (*outLen == 0) return WALLET_TOO_LARGE;
  showSigned(display);
  return WALLET_OK;
}

WalletStatus signEthMessage(Adafruit_SSD1306 &display, const uint8_t *msg, size_t len, Key k,
                            uint8_t sig[65]){
  beginScreen(display, "Sign ETH message?");
  for (size_t i = 0; i < len && i < 100; i++) {
    uint8_t c = msg[i];
    display.print((c >= 32 && c < 127) ? (char)c : '.');
  }
  if (len > 100) display.print("...");
  display.display();
  if (!askYesNo(display)) return WALLET_REJECTED;

  WalletStatus st = unlockWithPin(display, k);
  if (st != WALLET_OK) return st;
  uint8_t hash[32];
  ethPersonalMessageHash(msg, len, hash);
  signHash(k, hash, sig);
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

  uint8_t pin[5];
  if (!askPin(display, pin)) return WALLET_REJECTED;
  HDPrivateKey root;
  if (!hdUnlock(rec, pin, root)) {
    showWrongPin(display);
    return WALLET_WRONG_PIN;
  }
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
  if(askYesNo(display)){
    display.setTextSize(1);
    display.println("Are you sure you want to erase?");
    display.display();
    if(askYesNo(display)){
      uint16_t flag = 0xFFFF;
      eeprom.writeFlag(6, flag);
      Key k;
      k.privateKey.fill(0xFF);
      k.publicKey.fill(0xFF);
      for (int i = 0; i < 6; i++)
      {
        eeprom.storeKey(i, k);
      }
      eeprom.writeName(6, "");
      eeprom.eraseHd();
      forgetWalletAddresses();
      display.println("DONE!");
      display.display();
      delay(1000);
      return true;
    }
  }
  return false;
}
