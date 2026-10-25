#include "wallet.h"
#include "bip39.h"
#include "utils.h"
#define YES 38
#define NO 2

#ifndef A7
#define A7 A5   // fallback analog pin for boards without a 7th ADC channel
#endif

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
  // Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of
  // random noise). This can take a long time to generate random data if the result of analogRead(0)
  // doesn't change very frequently.
  while (size) {
    uint8_t val = 0;
    for (unsigned i = 0; i < 8; ++i) {
      int init = analogRead(0);
      int red = analogRead(1) & 0x01;
      unsigned int count = 0;
      while (analogRead(0) == init) {
        ++count;
      }

      if (count == 0) {
        init += red;
        val = (val << 1) | (init & 0x01);
      } else {
        count += red;
        val = (val << 1) | (count & 0x01);
      }
    }
    *dest = val;
    ++dest;
    --size;
  }
  // NOTE: it would be a good idea to hash the resulting random data using SHA-256 or similar.
  return 1;
}

size_t ethAddressFromKey(const Key &k, char out[43]){
  // Reconstruct the uncompressed public key (0x04 || x || y) from the
  // PIN-encrypted private key, then derive the Ethereum address.
  PrivateKey pk(k.privateKey.data(), true, &Mainnet);
  PublicKey pub = pk.publicKey();
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

  askPin(display, pin);
  display.setCursor(15, 0);
  display.print("Input pin again to verify");
  display.display();
  delay(2000);
  askPin(display, pin1);
  display.setCursor(15, 0);
  for(int i=0; i<5;i++)
    if(pin[i]!=pin1[i]){
      display.print("Pins do not match!");
      display.display();
      delay(2000);
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
  char mnem[200];
  s.toCharArray(mnem, sizeof(mnem));
  updateProgressBar(display,30);
  display.display();
  const char *pass = "";
  hdKey.fromMnemonic(mnem, strlen(mnem), pass, 0);
  updateProgressBar(display,40);
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

  // U2F placeholder  m/44'/99'/0'/0/0
  k.network = U2F;
  k.id = 3;
  k.nonce = 0;
  u2fKey.getSecret(k.privateKey.data());
  u2fKey.publicKey().sec(k.publicKey.data(), k.publicKey.size());
  xorKey(k, pin);
  eeprom.storeKey(3, k);
  updateProgressBar(display,90);
  display.display();

  // ETH  m/44'/60'/0'/0/0  (address shown as hex of pubkey; no keccak in this build)
  k.network = ETH;
  k.id = 1;
  k.nonce = 0;
  ethKey.getSecret(k.privateKey.data());
  ethKey.publicKey().sec(k.publicKey.data(), k.publicKey.size());
  xorKey(k, pin);
  eeprom.storeKey(1, k);
  updateProgressBar(display,100);
  display.display();

  // show and verify the 12 mnemonic words
  for (int q = 0 ; q < 2; q++){
    for (int i = 0; i < 12; i++)
    {
      display.clearDisplay();
      display.setCursor(15, 0);
      display.setTextSize(1);
      if(q==0){
        display.print("Write");
      }else{
        display.print("Verify");
      }
      display.setTextSize(2);
      display.setCursor(0, 20);
      display.print(i + 1);
      display.print(":");
      display.println(getWordsInString(s, ' ', i));
      display.display();
      delay(1000);
      displayYesNo(display);
      display.display();
      while(!digitalRead(YES))
      {
        delay(300);
      }
    }
  }

  uint16_t flag = GEN_FLAG;
  eeprom.writeFlag((unsigned char)6, flag);
}

void xorKey(Key &k, uint8_t *pin){
  uint8_t hash[32];
  sha256(pin, 5, hash);
  for(int i=0; i<32;i++)
  {
    k.privateKey[i] = k.privateKey[i] ^ hash[i];
  }
}

void askPin(Adafruit_SSD1306 &display, uint8_t *pin){
  display.clearDisplay();
  display.setCursor(15, 0);
  display.setTextColor(WHITE);
  display.println("Input pin");
  display.display();
  int num = analogRead(A7)/64;
  for(char i=0; i<5;)
  {
    delay(300);
    while(!digitalRead(YES)){
      num = analogRead(A7)/64;
      display.clearDisplay();
       display.setTextSize(1);
      display.setCursor(15, 0);
      display.println("Input pin\n\n");
      display.setTextSize(3);
      for(char v =0; v<5;v++){
        if(v==i){
          display.print(num, HEX);
        }else{display.print("*");}
      }
      if(digitalRead(NO)){
        return;
      }
      displayYesNo(display);
      display.display();
      delay(300);
    }
    pin[i++] = num;
    display.display();
  }
  for(int i=3; i>=1; i--){
    display.setCursor(0, 0);
    display.clearDisplay();
    display.print(i, DEC);
    display.display();
    display.clearDisplay();
    delay(500);
  }
}
boolean askYesNo(Adafruit_SSD1306 &display){
  delay(500);
  displayYesNo(display);
  display.display();
  display.clearDisplay();
  display.setCursor(0, 0);
  while(true) {
    if (digitalRead(NO)) {
      return false;
    }
    if (digitalRead(YES)) {
      return true;
    }
    delay(500);
  }
  return true;
}

char askXorY(Adafruit_SSD1306 &display, String x, String y){
  delay(500);
  displayXorY(display, x, y);
  while(true) {
    if (digitalRead(NO)) {
      return 'X';
    }
    if (digitalRead(YES)) {
      return 'Y';
    }
    delay(200);
  }
  return 'N';

}

boolean signBtc(Adafruit_SSD1306 &display, String data, Key k, boolean testnet){
  char hex[data.length()+1];
  byte raw[data.length()/2];
  data.toCharArray(hex, data.length()+1);
  size_t len = fromHex(hex, raw, sizeof(raw));
  Tx tx;
  tx.parse(raw, len);

  uint8_t pin[5];

  display.clearDisplay();
    display.setCursor(0, 0);
    display.setTextSize(1);
    display.println("Sign BTC Transaction?");
  float total = 0;
  for (int i = 0; i < tx.outputsNumber; i++) {
    total += ((float)tx.txOuts[i].amount) / 1e8;
  }
  display.print("Ins:"); display.print(tx.inputsNumber);
  display.print("-Outs:"); display.print(tx.outputsNumber);
  display.print(" T:"); display.print(total, 4); display.println(" BTC");
  for (int i = 0; i < tx.outputsNumber; i++) {
    display.print(tx.txOuts[i].address(testnet ? &Testnet : &Mainnet));
    display.print(":");
    display.print(((float)tx.txOuts[i].amount) / 1e8, 4);
    display.println(" BTC");
  }
  display.display();
  if(askYesNo(display)){
    askPin(display, pin);
    xorKey(k, pin);
    PrivateKey pk(k.privateKey.data(), true, testnet ? &Testnet : &Mainnet);
    for(int i=0; i<tx.inputsNumber; i++){
      Signature sig = tx.signInput(i, pk);
      tx.txIns[i].scriptSig.push(sig);
    }
    Serial.println(tx);
    return true;
  }
  return false;

}

boolean signEth(Adafruit_SSD1306 &display, String data, Key k){
  // `data` is expected to be a 64-hex-char (32-byte) Keccak-256 hash to sign.
  // This is the host/device split used by hardware wallets: the host builds the
  // Ethereum transaction, computes keccak256(rlp(unsigned_tx_with_chainid)),
  // and sends the 32-byte hash for the device to sign.
  uint8_t hash[32];
  size_t hlen = fromHex(data.c_str(), hash, 32);
  if (hlen != 32) {
    display.clearDisplay();
    display.setCursor(0, 0);
    display.setTextSize(1);
    display.println("Invalid ETH hash");
    display.println("(expect 64 hex chars)");
    display.display();
    delay(2000);
    return false;
  }

  // Show the hash being signed so the user can verify before confirming
  display.clearDisplay();
  display.setCursor(0, 0);
  display.setTextSize(1);
  display.println("Sign ETH hash?");
  display.println(data.substring(0, 16));
  display.println(data.substring(16, 32));
  display.display();
  if (!askYesNo(display)) return false;

  // Unlock the PIN-encrypted private key
  uint8_t pin[5];
  askPin(display, pin);
  xorKey(k, pin);

  // Sign the Keccak-256 hash with ECDSA secp256k1
  PrivateKey pk(k.privateKey.data(), true, &Mainnet);
  Signature sig = pk.sign(hash);

  // Signature::bin writes <r[32]><s[32]><index>
  uint8_t sigBin[66];
  sig.bin(sigBin, 66);
  uint8_t *r = sigBin;
  uint8_t *s = sigBin + 32;

  // EIP-155 replay-protection v byte (chainId=1 mainnet => 27/28 base;
  // host applies the chainId offset when assembling the signed tx)
  uint8_t v = 27;

  // Output components over Serial so the host can assemble the signed tx
  Serial.println("ETH SIGNED");
  Serial.println("R: " + toHex(r, 32));
  Serial.println("S: " + toHex(s, 32));
  Serial.println("V: " + String(v));

  // Show R and S as QR codes on screen
  display.clearDisplay();
  display.setCursor(0, 0);
  display.setTextSize(1);
  display.println("ETH Signed");
  display.println("R/S via QR");
  display.display();

  QRCode qrcodeR;
  uint8_t qrcodeDataR[qrcode_getBufferSize(3)];
  String rStr = String("R:") + toHex(r, 32);
  qrcode_initText(&qrcodeR, qrcodeDataR, 3, 0, rStr.c_str());
  displayQrCode(display, qrcodeR, 0);

  QRCode qrcodeS;
  uint8_t qrcodeDataS[qrcode_getBufferSize(3)];
  String sStr = String("S:") + toHex(s, 32);
  qrcode_initText(&qrcodeS, qrcodeDataS, 3, 0, sStr.c_str());
  displayQrCode(display, qrcodeS, 64);

  display.display();
  delay(4000);
  while (!digitalRead(YES)) {
    delay(200);
  }
  return true;
}

void eraseDevice(Adafruit_SSD1306 &display, SecureStorage &eeprom){
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
      char name[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
      eeprom.writeName(6, name);
      display.println("DONE!");
      display.display();
      delay(1000);
    }
  }

}
