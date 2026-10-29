// Secure element probe firmware (env:setest_*), built in place of main.cpp.
//
// Phase 1 of docs/ATECC_PLAN.md: checks that the ATECC508A (U4) answers on
// the I2C bus shared with the EEPROM and the OLED, dumps and decodes its
// config zone and compares the slot configuration with the planned map in
// src/se/se_layout.h. Read-only: the driver cannot write or lock the chip.
// The result is shown on the OLED at boot; send '?' on USB serial for the
// command list.
#include <Arduino.h>
#include <Adafruit_SSD1306.h>
#include "se/atecc.h"
#include "se/se_layout.h"

static Adafruit_SSD1306 display(128, 64, &Wire, 4);
static Atecc se;

static void printHex(uint8_t b) {
  if (b < 0x10) Serial.print('0');
  Serial.print(b, HEX);
}

static void printHex16(uint16_t v) {
  Serial.print("0x");
  printHex(v >> 8);
  printHex(v & 0xFF);
}

static void printStatus(const char *what, uint8_t st) {
  Serial.print(what);
  Serial.print(": ");
  printHex(st);
  Serial.print(" (");
  Serial.print(ateccStatusName(st));
  Serial.println(")");
}

static void oled(const char *l1, const char *l2 = "", const char *l3 = "", const char *l4 = "") {
  display.clearDisplay();
  display.setTextColor(WHITE);
  display.setTextSize(1);
  display.setCursor(0, 0);
  display.println("SE probe (read-only)");
  display.println();
  display.println(l1);
  display.println(l2);
  display.println(l3);
  display.println(l4);
  display.display();
}

/* ------------------------------------------------------------------ */
/* Report                                                              */
/* ------------------------------------------------------------------ */

static void scanBus() {
  se.wake();   // an asleep ATECC does not ACK its address
  Serial.print("I2C devices:");
  for (uint8_t a = 1; a < 0x78; a++) {
    Wire.beginTransmission(a);
    if (Wire.endTransmission() == 0) {
      Serial.print(" 0x");
      printHex(a);
      if (a == 0x3C) Serial.print("(OLED)");
      else if (a == 0x50) Serial.print("(EEPROM)");
      else if (a == ATECC_ADDRESS) Serial.print("(ATECC)");
    }
  }
  Serial.println();
  se.sleep();
}

static const char *otpModeName(uint8_t m) {
  switch (m) {
    case 0xAA: return "read-only";
    case 0x55: return "consumption";
    case 0x00: return "legacy";
    default:   return "?";
  }
}

static void printConfig(const uint8_t *cfg) {
  Serial.println("Config zone:");
  for (int row = 0; row < ATECC_CONFIG_SIZE; row += 16) {
    Serial.print("  ");
    if (row < 0x10) Serial.print('0');
    Serial.print(row, HEX);
    Serial.print(":");
    for (int i = 0; i < 16; i++) {
      Serial.print(' ');
      printHex(cfg[row + i]);
    }
    Serial.println();
  }

  uint8_t sn[9];
  seSerial(cfg, sn);
  Serial.print("Serial:      ");
  for (int i = 0; i < 9; i++) printHex(sn[i]);
  bool genuine = sn[0] == 0x01 && sn[1] == 0x23 && sn[8] == 0xEE;
  Serial.println(genuine ? "" : "  (unexpected 01 23 .. EE pattern!)");
  Serial.print("I2C address: 0x");
  printHex(cfg[SE_CFG_I2C_ADDR]);
  Serial.println(" (8-bit)");
  Serial.print("OTP mode:    0x");
  printHex(cfg[SE_CFG_OTP_MODE]);
  Serial.print(" ");
  Serial.println(otpModeName(cfg[SE_CFG_OTP_MODE]));
  Serial.print("ChipMode:    0x");
  printHex(cfg[SE_CFG_CHIP_MODE]);
  Serial.println((cfg[SE_CFG_CHIP_MODE] & 0x04) ? " (watchdog 10 s)" : " (watchdog 1.3 s)");
  Serial.print("Config zone: ");
  Serial.println(seConfigLocked(cfg) ? "LOCKED" : "unlocked");
  Serial.print("Data zone:   ");
  Serial.println(seDataLocked(cfg) ? "LOCKED" : "unlocked");
}

static void printSlots(const uint8_t *cfg) {
  Serial.println("Slot  role            SlotCfg KeyCfg | plan:  SlotCfg KeyCfg");
  int diffs = 0;
  for (int s = 0; s < SE_SLOTS; s++) {
    uint16_t sc = seSlotConfig(cfg, s), kc = seKeyConfig(cfg, s);
    bool same = sc == SE_PLAN[s].slotConfig && kc == SE_PLAN[s].keyConfig;
    diffs += !same;
    char line[24];
    snprintf(line, sizeof(line), "%2d    %-15s ", s, SE_PLAN[s].role);
    Serial.print(line);
    printHex16(sc); Serial.print(' ');
    printHex16(kc); Serial.print(" |        ");
    printHex16(SE_PLAN[s].slotConfig); Serial.print(' ');
    printHex16(SE_PLAN[s].keyConfig);
    if (seSlotLocked(cfg, s)) Serial.print("  SLOT LOCKED");
    Serial.println(same ? "" : "  *");
  }
  Serial.print(diffs);
  Serial.println(" slot(s) differ from the plan (*).");
  if (!seConfigLocked(cfg)) {
    Serial.println("Config unlocked: the plan can still be applied (phase 2).");
  } else if (diffs) {
    Serial.println("Config LOCKED with a different layout: the plan cannot be applied to this chip.");
  }
}

static void report() {
  Serial.println();
  scanBus();
  uint8_t rev[4];
  uint8_t st = se.info(rev);
  printStatus("Info", st);
  if (st != ATECC_SUCCESS) {
    oled("ATECC: no answer", ateccStatusName(st));
    return;
  }
  Serial.print("Revision:    ");
  for (int i = 0; i < 4; i++) printHex(rev[i]);
  Serial.println(rev[2] == ATECC_REV_508A ? " (ATECC508A)" : " (not an ATECC508A!)");

  uint8_t cfg[ATECC_CONFIG_SIZE];
  st = se.readConfig(cfg);
  printStatus("Read config", st);
  if (st != ATECC_SUCCESS) {
    oled("ATECC: config read", ateccStatusName(st));
    return;
  }
  printConfig(cfg);
  printSlots(cfg);

  uint8_t sn[9];
  seSerial(cfg, sn);
  char snText[19];
  for (int i = 0; i < 9; i++) snprintf(snText + 2 * i, 3, "%02X", sn[i]);
  oled(rev[2] == ATECC_REV_508A ? "ATECC508A answers" : "unknown chip!", snText,
       seConfigLocked(cfg) ? "config: LOCKED" : "config: unlocked",
       seDataLocked(cfg) ? "data:   LOCKED" : "data:   unlocked");
}

/* ------------------------------------------------------------------ */
/* Stress test: the ATECC between OLED updates on the shared bus       */
/* ------------------------------------------------------------------ */

static void stress() {
  const int rounds = 300;
  uint8_t ref[ATECC_CONFIG_SIZE], cfg[ATECC_CONFIG_SIZE], rev[4];
  if (se.readConfig(ref) != ATECC_SUCCESS) {
    Serial.println("Stress: no reference config, run 'i' first.");
    return;
  }
  Serial.print("Stress: ");
  Serial.print(rounds);
  Serial.println(" x (Info + config read + OLED frame)...");
  int fail = 0, mismatch = 0;
  uint32_t start = millis();
  for (int r = 0; r < rounds; r++) {
    uint8_t st = se.info(rev);
    if (st == ATECC_SUCCESS) st = se.readConfig(cfg);
    if (st != ATECC_SUCCESS) {
      fail++;
      printStatus("  round failed", st);
    } else if (memcmp(cfg, ref, sizeof(cfg)) != 0) {
      mismatch++;
    }
    char l[22];
    snprintf(l, sizeof(l), "round %d/%d", r + 1, rounds);
    oled("Stress test", l);
  }
  uint32_t ms = millis() - start;
  Serial.print("Failures: ");   Serial.print(fail);
  Serial.print(", config mismatches: "); Serial.print(mismatch);
  Serial.print(", ");           Serial.print(ms / rounds);
  Serial.println(" ms per round.");
  Serial.println(fail || mismatch ? "Stress: FAILED" : "Stress: OK");
}

static void printHelp() {
  Serial.println();
  Serial.println("Soteria secure element probe (read-only, never writes or locks)");
  Serial.println("  i  report: bus scan, Info, config zone, slot map vs plan");
  Serial.println("  s  stress test: 300 rounds sharing the bus with the OLED");
  Serial.println("  ?  this help");
}

void setup() {
  Serial.begin(115200);
  Wire.begin();
  display.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  display.setRotation(2);
  oled("waiting for USB", "serial (115200)...");
  while (!Serial) {}
  printHelp();
  report();
}

void loop() {
  if (!Serial.available()) return;
  switch (Serial.read()) {
    case 'i': report(); break;
    case 's': stress(); break;
    case '\r': case '\n': break;
    default: printHelp();
  }
}
