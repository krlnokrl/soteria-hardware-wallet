// Secure element provisioning firmware (env:seprov_*), built in place of
// main.cpp. Phase 2 of docs/ATECC_PLAN.md: puts the planned slot map
// (src/se/se_layout.h) into the ATECC508A, locks it and checks that every
// rule works as intended.
//
// Driven over USB serial, one command per line ('?' lists them). The two
// IRREVERSIBLE steps need the exact phrases "LOCK CONFIG" and "LOCK DATA":
//   c            write SlotConfig/KeyConfig (config still unlocked, redoable)
//   LOCK CONFIG  lock the config zone (CRC-checked against the plan)
//   d            write the factory state: random P and W (chip RNG mixed
//                with A0 noise), public PIN/PUK verifiers, zeros elsewhere;
//                P goes to the EEPROM (redoable until the data lock)
//   LOCK DATA    lock the data zone, generate the P-256 keys, run 'v'
//   v            verify the rules: encrypted read/write with P, PIN and
//                PUK keys, clear reads refused for secrets, wrong keys
//                refused, MAC with W (if W is still in RAM)
//   WALLET TEST  run the wallet code (src/se/se_wallet.cpp) on the chip
//                with test PINs: create, unlock, wrong PIN count, change
//                PIN, wipe, factory reset; times the PIN check. Needs the
//                chip in factory state and leaves it there.
#include <Arduino.h>
#include <Adafruit_SSD1306.h>
#include <Hash.h>
#include "wallet.h"
#include "se/atecc.h"
#include "se/se_layout.h"
#include "se/se_keys.h"
#include "se/se_wallet.h"

static Adafruit_SSD1306 display(128, 64, &Wire, 4);
static SecureStorage eeprom(0x50);
static Atecc se;

// Set by 'd' for 'LOCK DATA' and the MAC check; lost on reset.
static bool s_dataWritten = false;
static uint8_t s_stretch[32];

static void printHex(const uint8_t *d, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (d[i] < 0x10) Serial.print('0');
    Serial.print(d[i], HEX);
  }
}

static void oled(const char *l1, const char *l2 = "") {
  display.clearDisplay();
  display.setTextColor(WHITE);
  display.setTextSize(1);
  display.setCursor(0, 0);
  display.println("SE provisioning");
  display.println("(USB serial)");
  display.println();
  display.println(l1);
  display.println(l2);
  display.display();
}

static bool ok(const char *what, uint8_t st) {
  Serial.print(st == ATECC_SUCCESS ? "  ok    " : "  FAIL  ");
  Serial.print(what);
  if (st != ATECC_SUCCESS) {
    Serial.print(": ");
    Serial.print(ateccStatusName(st));
  }
  Serial.println();
  return st == ATECC_SUCCESS;
}

static bool check(const char *what, bool cond) {
  Serial.print(cond ? "  ok    " : "  FAIL  ");
  Serial.println(what);
  return cond;
}

static bool readState(uint8_t cfg[ATECC_CONFIG_SIZE]) {
  return ok("read config", se.readConfig(cfg));
}

/* ------------------------------------------------------------------ */
/* Status                                                              */
/* ------------------------------------------------------------------ */

static void status() {
  uint8_t cfg[ATECC_CONFIG_SIZE], want[ATECC_CONFIG_SIZE];
  if (!readState(cfg)) return;
  seBuildConfig(cfg, want);
  int diffs = 0;
  for (int s = 0; s < SE_SLOTS; s++) {
    if (seSlotConfig(cfg, s) != SE_PLAN[s].slotConfig || seKeyConfig(cfg, s) != SE_PLAN[s].keyConfig) {
      diffs++;
    }
  }
  uint8_t sn[9];
  seSerial(cfg, sn);
  Serial.print("Serial ");       printHex(sn, 9);
  Serial.print("  config ");     Serial.print(seConfigLocked(cfg) ? "LOCKED" : "unlocked");
  Serial.print("  data ");       Serial.print(seDataLocked(cfg) ? "LOCKED" : "unlocked");
  Serial.print("  slots differing from plan: "); Serial.println(diffs);
  Serial.print("Planned config CRC: 0x");
  Serial.println(Atecc::crc16(want, ATECC_CONFIG_SIZE), HEX);
  SeRecord rec;
  bool paired = eeprom.readSe(rec) && memcmp(rec.serial, sn, 9) == 0;
  Serial.print("EEPROM pairing record: ");
  Serial.println(paired ? "present for this chip" : "none");
  oled(seDataLocked(cfg) ? "data: LOCKED" : seConfigLocked(cfg) ? "config: LOCKED" : "unlocked",
       diffs ? "config differs" : "config = plan");
}

/* ------------------------------------------------------------------ */
/* Config                                                              */
/* ------------------------------------------------------------------ */

static void writeConfig() {
  uint8_t cfg[ATECC_CONFIG_SIZE], want[ATECC_CONFIG_SIZE];
  if (!readState(cfg)) return;
  if (!check("config zone unlocked", !seConfigLocked(cfg))) return;
  seBuildConfig(cfg, want);
  if (!ok("write SlotConfig/KeyConfig", se.writeSlotConfig(want))) return;
  if (!readState(cfg)) return;
  check("read back = plan", memcmp(cfg, want, ATECC_CONFIG_SIZE) == 0);
  Serial.println("Config written, not locked. Check it with 'i', then type LOCK CONFIG.");
}

static void lockConfig() {
  uint8_t cfg[ATECC_CONFIG_SIZE], want[ATECC_CONFIG_SIZE];
  if (!readState(cfg)) return;
  if (!check("config zone unlocked", !seConfigLocked(cfg))) return;
  seBuildConfig(cfg, want);
  if (!check("chip config = plan", memcmp(cfg, want, ATECC_CONFIG_SIZE) == 0)) {
    Serial.println("Run 'c' first.");
    return;
  }
  uint16_t crc = Atecc::crc16(want, ATECC_CONFIG_SIZE);
  Serial.print("Locking config zone, CRC 0x");
  Serial.println(crc, HEX);
  ok("lock config", se.lockConfig(crc));
  if (readState(cfg)) check("config zone now locked", seConfigLocked(cfg));
  status();
}

/* ------------------------------------------------------------------ */
/* Data                                                                */
/* ------------------------------------------------------------------ */

// 32 bytes from the chip RNG mixed with A0 noise; false if the chip
// returned its unlocked-config test pattern.
static bool secretFromRng(const char *label, uint8_t out[32]) {
  uint8_t chip[32], a0[32];
  if (!ok("chip random", se.random(chip))) return false;
  bool fixed = true;
  for (int i = 0; i < 32; i++) fixed &= chip[i] == ((i & 3) < 2 ? 0xFF : 0x00);
  if (!check("chip random is not the fixed test pattern", !fixed)) return false;
  RNGpin(a0, sizeof(a0));
  se.mixHostEntropy(a0, sizeof(a0));
  SHA256 h;
  h.write((const uint8_t *)label, strlen(label));
  h.write(chip, sizeof(chip));
  h.write(a0, sizeof(a0));
  h.end(out);
  memset(chip, 0, sizeof(chip));
  memset(a0, 0, sizeof(a0));
  return true;
}

static void writeData() {
  uint8_t cfg[ATECC_CONFIG_SIZE];
  if (!readState(cfg)) return;
  if (!check("config zone locked", seConfigLocked(cfg))) return;
  if (!check("data zone unlocked", !seDataLocked(cfg))) return;
  uint8_t sn[9];
  seSerial(cfg, sn);

  uint8_t pairing[32];
  if (!secretFromRng("soteria-pairing", pairing)) return;
  if (!secretFromRng("soteria-stretch", s_stretch)) return;

  uint8_t buf[416];
  bool good = true;
  for (int s = 0; s < SE_SLOTS && good; s++) {
    memset(buf, 0, sizeof(buf));
    if (s == SE_SLOT_PAIRING) memcpy(buf, pairing, 32);
    if (s == SE_SLOT_PIN)     seFactoryPin(sn, buf);
    if (s == SE_SLOT_PUK)     seFactoryPuk(sn, buf);
    if (s == SE_SLOT_STRETCH) memcpy(buf, s_stretch, 32);
    char what[32];
    snprintf(what, sizeof(what), "slot %d (%s)", s, SE_PLAN[s].role);
    uint8_t st = se.writeSlotClear(s, buf, seSlotSize(s));
    // GenKey replaces the private key slots after the lock anyway
    bool keySlot = SE_PLAN[s].keyConfig & KC_PRIVATE;
    if (!ok(what, st) && !keySlot) good = false;
  }
  memset(buf, 0, sizeof(buf));
  if (!good) return;

  SeRecord rec;
  memset(&rec, 0, sizeof(rec));
  rec.magic = SE_RECORD_MAGIC;
  memcpy(rec.serial, sn, 9);
  memcpy(rec.pairing, pairing, 32);
  eeprom.writeSe(rec);
  SeRecord back;
  check("pairing record in EEPROM", eeprom.readSe(back) && memcmp(&back, &rec, sizeof(rec)) == 0);
  memset(&rec, 0, sizeof(rec));
  memset(pairing, 0, sizeof(pairing));
  s_dataWritten = true;
  Serial.println("Factory state written, not locked. Type LOCK DATA to lock it.");
}

static void verify();

static void lockData() {
  uint8_t cfg[ATECC_CONFIG_SIZE];
  if (!readState(cfg)) return;
  if (!check("config zone locked", seConfigLocked(cfg))) return;
  if (!check("data zone unlocked", !seDataLocked(cfg))) return;
  if (!check("factory state written in this session ('d')", s_dataWritten)) return;
  ok("lock data", se.lockData());
  if (!readState(cfg) || !check("data zone now locked", seDataLocked(cfg))) return;

  const uint8_t keys[] = { SE_SLOT_IDENTITY, SE_SLOT_SPARE_KEY1, SE_SLOT_SPARE_KEY2 };
  for (uint8_t s : keys) {
    uint8_t pub[64];
    char what[32];
    snprintf(what, sizeof(what), "GenKey slot %d", s);
    if (ok(what, se.genKey(s, pub)) && s == SE_SLOT_IDENTITY) {
      Serial.print("  identity public key: 04");
      printHex(pub, 64);
      Serial.println();
    }
  }
  verify();
  status();
}

/* ------------------------------------------------------------------ */
/* Verification                                                        */
/* ------------------------------------------------------------------ */

// Write a test pattern encrypted, read it back (clear or encrypted),
// restore zeros.
static bool roundTrip(const char *what, uint8_t slot, uint8_t keySlot, const uint8_t key[32],
                      bool encryptedRead) {
  uint8_t pattern[32], back[32], zeros[32] = { 0 };
  for (int i = 0; i < 32; i++) pattern[i] = (uint8_t)(0xA5 ^ (i * 7) ^ slot);
  char line[64];
  snprintf(line, sizeof(line), "%s: encrypted write", what);
  bool good = ok(line, se.writeEncrypted(slot, 0, keySlot, key, pattern));
  snprintf(line, sizeof(line), "%s: %s read back", what, encryptedRead ? "encrypted" : "clear");
  uint8_t st = encryptedRead ? se.readEncrypted(slot, 0, keySlot, key, back) : se.read32(slot, 0, back);
  good &= ok(line, st) && check("  ... matches", memcmp(back, pattern, 32) == 0);
  snprintf(line, sizeof(line), "%s: restore zeros", what);
  good &= ok(line, se.writeEncrypted(slot, 0, keySlot, key, zeros));
  return good;
}

static bool refused(const char *what, uint8_t st) {
  return check(what, st != ATECC_SUCCESS);
}

static void verify() {
  uint8_t cfg[ATECC_CONFIG_SIZE];
  if (!readState(cfg)) return;
  if (!check("config and data zones locked", seConfigLocked(cfg) && seDataLocked(cfg))) return;
  uint8_t sn[9], pin[32], puk[32], wrong[32], out[32];
  seSerial(cfg, sn);
  seFactoryPin(sn, pin);
  seFactoryPuk(sn, puk);
  memset(wrong, 0x5A, sizeof(wrong));
  SeRecord rec;
  if (!check("pairing record in EEPROM for this chip",
             eeprom.readSe(rec) && memcmp(rec.serial, sn, 9) == 0)) return;

  int fails = 0;
  fails += !check("chip random works", se.random(out) == ATECC_SUCCESS);
  fails += !roundTrip("fw policy (PUK)", SE_SLOT_FW_POLICY, SE_SLOT_PUK, puk, false);
  fails += !roundTrip("PIN counter (PIN)", SE_SLOT_PIN_COUNT, SE_SLOT_PIN, pin, false);
  fails += !roundTrip("FIDO2 secret (P)", SE_SLOT_FIDO, SE_SLOT_PAIRING, rec.pairing, true);
  fails += !roundTrip("wallet seed (PIN)", SE_SLOT_SEED, SE_SLOT_PIN, pin, true);

  fails += !refused("seed: clear read refused", se.read32(SE_SLOT_SEED, 0, out));
  fails += !refused("FIDO2: clear read refused", se.read32(SE_SLOT_FIDO, 0, out));
  fails += !refused("PIN verifier: clear read refused", se.read32(SE_SLOT_PIN, 0, out));
  fails += !refused("seed: read via pairing key refused",
                    se.readEncrypted(SE_SLOT_SEED, 0, SE_SLOT_PAIRING, rec.pairing, out));
  fails += !refused("fw policy: write with PIN key refused",
                    se.writeEncrypted(SE_SLOT_FW_POLICY, 0, SE_SLOT_PIN, pin, wrong));
  fails += !refused("fw policy: write with wrong PUK refused",
                    se.writeEncrypted(SE_SLOT_FW_POLICY, 0, SE_SLOT_PUK, wrong, wrong));
  fails += !refused("seed: clear write refused", se.writeSlotClear(SE_SLOT_SEED, wrong, 32));

  // Wrong PIN: the encrypted read "works" but yields garbage
  uint8_t zeros[32] = { 0 };
  fails += !check("seed: wrong PIN reads garbage",
                  se.readEncrypted(SE_SLOT_SEED, 0, SE_SLOT_PIN, wrong, out) == ATECC_SUCCESS &&
                  memcmp(out, zeros, 32) != 0);

  uint8_t challenge[32], expect[32];
  for (int i = 0; i < 32; i++) challenge[i] = (uint8_t)i;
  if (ok("MAC with stretch secret W", se.mac(SE_SLOT_STRETCH, challenge, out))) {
    if (s_dataWritten) {
      seExpectedMac(s_stretch, challenge, SE_SLOT_STRETCH, sn, expect);
      fails += !check("  ... matches the host computation", memcmp(out, expect, 32) == 0);
    } else {
      Serial.println("  (W not in RAM after a reset: MAC value not checked)");
    }
  } else {
    fails++;
  }
  uint8_t pub[64];
  fails += !ok("identity public key", se.publicKey(SE_SLOT_IDENTITY, pub));

  // The PUK reaches the hidden keys: rewrite each with its current value
  // (a wrong MAC is refused by the chip, so nothing can change here).
  uint8_t value[32];
  fails += !ok("PUK rewrites pairing P (same value)",
               se.writeEncrypted(SE_SLOT_PAIRING, 0, SE_SLOT_PUK, puk, rec.pairing));
  fails += !ok("PUK rewrites PIN verifier (same value)",
               se.writeEncrypted(SE_SLOT_PIN, 0, SE_SLOT_PUK, puk, pin));
  memcpy(value, puk, 32);
  fails += !ok("PUK rewrites itself (same value)",
               se.writeEncrypted(SE_SLOT_PUK, 0, SE_SLOT_PUK, puk, value));
  if (s_dataWritten) {
    fails += !ok("PUK rewrites stretch W (same value)",
                 se.writeEncrypted(SE_SLOT_STRETCH, 0, SE_SLOT_PUK, puk, s_stretch));
  }
  fails += !refused("PIN cannot rewrite the PUK",
                    se.writeEncrypted(SE_SLOT_PUK, 0, SE_SLOT_PIN, pin, puk));
  fails += !roundTrip("after rewrites: seed (PIN)", SE_SLOT_SEED, SE_SLOT_PIN, pin, true);
  fails += !roundTrip("after rewrites: FIDO2 (P)", SE_SLOT_FIDO, SE_SLOT_PAIRING, rec.pairing, true);
  memset(value, 0, sizeof(value));

  memset(&rec, 0, sizeof(rec));
  Serial.print("Verification: ");
  Serial.println(fails ? "FAILED" : "all checks passed");
  oled(fails ? "verify FAILED" : "verified OK");
}

/* ------------------------------------------------------------------ */
/* Wallet self-test                                                    */
/* ------------------------------------------------------------------ */

static bool expect(const char *what, SeResult got, SeResult want) {
  Serial.print(got == want ? "  ok    " : "  FAIL  ");
  Serial.print(what);
  Serial.print(": ");
  Serial.println(seResultText(got));
  return got == want;
}

static void walletTest() {
  SeWallet w;
  if (!check("secure element ready and paired", w.begin(se, eeprom))) return;
  static const uint8_t pin[SE_PIN_DIGITS]   = { 1, 2, 3, 4, 5, 6 };
  static const uint8_t pin2[SE_PIN_DIGITS]  = { 0xA, 0xB, 0xC, 0xD, 0xE, 0xF };
  static const uint8_t wrong[SE_PIN_DIGITS] = { 1, 2, 3, 4, 5, 7 };
  uint8_t root[SE_ROOT_SIZE], fido[32], out[SE_ROOT_SIZE], puk[SE_PUK_DIGITS], puk2[SE_PUK_DIGITS];
  w.random(root, sizeof(root));
  w.random(fido, sizeof(fido));
  int fails = 0;

  uint32_t t = millis();
  SeResult r = w.create(pin, root, fido, nullptr, puk);
  if (r == SE_NEED_PUK) {
    Serial.println("  Chip holds a PUK (not in factory state): test skipped.");
    return;
  }
  fails += !expect("create (factory state)", r, SE_OK);
  Serial.print("        create took "); Serial.print(millis() - t); Serial.println(" ms");

  uint32_t failed = 99;
  t = millis();
  fails += !expect("unlock", w.unlock(pin, out, &failed), SE_OK);
  Serial.print("        unlock (PIN check) took "); Serial.print(millis() - t); Serial.println(" ms");
  fails += !check("  ... root matches, 0 failed attempts", memcmp(out, root, sizeof(root)) == 0 && failed == 0);
  t = millis();
  fails += !expect("wrong PIN refused", w.unlock(wrong, out, nullptr), SE_WRONG_PIN);
  Serial.print("        wrong PIN took "); Serial.print(millis() - t); Serial.println(" ms");
  fails += !expect("unlock after a wrong PIN", w.unlock(pin, out, &failed), SE_OK);
  fails += !check("  ... reports 1 failed attempt", failed == 1);

  uint8_t secret[32];
  fails += !check("FIDO2 secret readable without PIN", w.fidoSecret(secret) && memcmp(secret, fido, 32) == 0);
  uint32_t c1 = 0, c2 = 0;
  fails += !check("FIDO2 counter increments", w.fidoCounter(c1, false) && w.fidoCounter(c2, true) && c2 == c1 + 1);

  fails += !expect("new wallet without PUK refused", w.create(pin, root, fido, nullptr, puk2), SE_NEED_PUK);
  fails += !expect("change PIN", w.changePin(pin, puk, pin2), SE_OK);
  fails += !expect("old PIN refused", w.unlock(pin, out, nullptr), SE_WRONG_PIN);
  fails += !expect("new PIN works", w.unlock(pin2, out, nullptr), SE_OK);
  fails += !check("  ... root matches", memcmp(out, root, sizeof(root)) == 0);
  fails += !expect("wipe with PIN", w.wipe(pin2), SE_OK);
  fails += !check("FIDO2 secret gone", !w.fidoSecret(secret));
  fails += !expect("new wallet with PUK", w.create(pin, root, fido, puk, puk2), SE_OK);
  fails += !expect("factory reset with old PUK refused", w.factoryReset(puk), SE_WRONG_PUK);
  fails += !expect("factory reset with new PUK", w.factoryReset(puk2), SE_OK);
  fails += !expect("PIN gone after factory reset", w.unlock(pin, out, nullptr), SE_WRONG_PIN);
  // Factory state again: a create without PUK must work; reset it again.
  fails += !expect("create in factory state", w.create(pin2, root, fido, nullptr, puk), SE_OK);
  fails += !expect("factory reset", w.factoryReset(puk), SE_OK);

  memset(root, 0, sizeof(root));
  memset(out, 0, sizeof(out));
  Serial.print("Wallet self-test: ");
  Serial.println(fails ? "FAILED" : "all checks passed (chip back in factory state)");
  oled(fails ? "wallet test FAILED" : "wallet test OK");
}

/* ------------------------------------------------------------------ */
/* Command line                                                        */
/* ------------------------------------------------------------------ */

static void printHelp() {
  Serial.println();
  Serial.println("Soteria secure element provisioning (one command per line)");
  Serial.println("  i            status");
  Serial.println("  c            write SlotConfig/KeyConfig (config unlocked)");
  Serial.println("  LOCK CONFIG  IRREVERSIBLE: lock the config zone");
  Serial.println("  d            write the factory state (config locked, data unlocked)");
  Serial.println("  LOCK DATA    IRREVERSIBLE: lock the data zone, GenKey, verify");
  Serial.println("  v            verify the slot rules (both zones locked)");
  Serial.println("  WALLET TEST  wallet code on the chip (factory state, restored)");
}

static void run(const String &cmd) {
  Serial.print("> ");
  Serial.println(cmd);
  if (cmd == "i") status();
  else if (cmd == "c") writeConfig();
  else if (cmd == "LOCK CONFIG") lockConfig();
  else if (cmd == "d") writeData();
  else if (cmd == "LOCK DATA") lockData();
  else if (cmd == "v") verify();
  else if (cmd == "WALLET TEST") walletTest();
  else printHelp();
}

void setup() {
  Serial.begin(115200);
  Wire.begin();
  display.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  display.setRotation(2);
  oled("waiting for USB", "serial (115200)...");
  while (!Serial) {}
  printHelp();
  status();
}

void loop() {
  static String line;
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\r') continue;
    if (c == '\n') {
      line.trim();
      if (line.length()) run(line);
      line = "";
    } else if (line.length() < 32) {
      line += c;
    }
  }
}
