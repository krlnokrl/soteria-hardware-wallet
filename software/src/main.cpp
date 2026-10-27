#include <Arduino.h>
#include <wallet.h>
#include "utils.h"
#include <qrcode.h>
#include "u2f.h"
#include "protocol.h"
#include "buttons.h"

#define ROTATE_IDLE_MS  60000UL    // start rotating coins after this long untouched
#define ROTATE_EVERY_MS 20000UL
#define SAVER_IDLE_MS   180000UL   // then hide the addresses (privacy, OLED burn-in)
#define REFRESH_MS      2000UL     // redraw at least this often (after USB prompts)

Adafruit_SSD1306 display(128, 64, &Wire, 4);

SecureStorage eeprom(0x50);

void setup() {
  Serial.begin(115200);
  Wire.begin();
  display.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  display.setRotation(2);
  display.clearDisplay();
  pinMode(YES, INPUT);
  pinMode(NO, INPUT);

  gU2F.begin(display, eeprom);   // initialise the USB HID / CTAPHID U2F interface
  gProtocol.begin(display, eeprom);   // JSON host protocol on USB serial
}

// Addresses shown on the main screen, derived once per wallet load.
struct WalletView {
  String name;
  const char *label[3];
  char addr[3][96];
};

static void loadWallet(WalletView &w) {
  eeprom.getName(6, w.name);
  const WalletAddresses &a = walletAddresses(eeprom);
  if (a.segwit) {
    w.label[0] = "BTC";
    w.label[1] = "BTC testnet";
    strcpy(w.addr[0], a.btc);
    strcpy(w.addr[1], a.btcTest);
  } else {   // wallet created before SegWit support
    w.label[0] = "BTC legacy";
    w.label[1] = "BTC test legacy";
    strcpy(w.addr[0], a.btcLegacy);
    strcpy(w.addr[1], a.btcTestLegacy);
  }
  w.label[2] = "ETH / EVM";
  strcpy(w.addr[2], a.eth);
}

static void beginFrame() {
  display.clearDisplay();
  display.setTextColor(WHITE);
  display.setTextSize(1);
  display.setCursor(0, 0);
}

// Name and coin on the left, the address in 10-character lines below
// them (the left column ends where the QR code starts), QR on the right.
static void renderQr(const WalletView &w, int coin) {
  beginFrame();
  display.println(w.name.length() ? w.name.c_str() : "Soteria");
  display.println(w.label[coin]);
  display.println();
  const char *a = w.addr[coin];
  for (int i = 0; a[i]; i++) {
    if (i > 0 && i % 10 == 0) display.println();
    display.print(a[i]);
  }
  QRCode qrcode;
  uint8_t qrcodeData[qrcode_getBufferSize(3)];
  qrcode_initText(&qrcode, qrcodeData, 3, ECC_MEDIUM, a);
  displayQrCode(display, qrcode, 68);
  display.display();
}

// Full-width address in groups of 4 for checking it against another screen.
static void renderVerify(const WalletView &w, int coin) {
  beginFrame();
  display.print(w.label[coin]);
  display.println(" address");
  display.println();
  displayGrouped(display, w.addr[coin]);
  display.setCursor(0, 56);
  display.print("NO: QR   YES: next");
  display.display();
}

// Screen saver: only the logo and name, moving every minute.
static void renderSaver(const WalletView &w) {
  static const uint8_t X[4] = { 0, 96, 48, 20 };
  static const uint8_t Y[4] = { 0, 20, 32, 8 };
  int pos = (millis() / 60000UL) % 4;
  beginFrame();
  display.drawBitmap(X[pos], Y[pos], logo, 32, 32, 1);
  display.display();
}

static void renderCreate() {
  beginFrame();
  display.println("No wallet yet.");
  display.println();
  display.println("Create a new wallet?");
  display.println("(set a PIN, then");
  display.println("write down 12 words)");
  display.setCursor(95, 57);
  display.setTextColor(BLACK, WHITE);
  display.print(" Yes ");
  display.setTextColor(WHITE);
  display.display();
}

void loop() {
  if (eeprom.readFlag(6) != GEN_FLAG) {
    renderCreate();
    buttonsArm();
    for (;;) {
      gU2F.poll();   // keep servicing USB while we wait for the button
      gProtocol.poll();
      if (buttonsPoll() == BTN_YES) break;
      delay(5);
    }
    generateWallet(display, eeprom);
    return;
  }

  // Address derivation is slow EC math: do it once, not every frame.
  WalletView w;
  loadWallet(w);
  int coin = 0;
  bool verify = false, saver = false, dirty = true;
  uint32_t lastInput = millis(), lastRotate = millis(), lastDraw = 0;
  buttonsArm();

  for (;;) {
    uint32_t t0 = millis();
    gU2F.poll();
    gProtocol.poll();
    if (gProtocol.walletChanged()) return;   // erased or renamed: reload
    if (millis() - t0 > 100) {
      // A USB request used the screen and buttons: redraw, and require a
      // fresh press so its answer does not also act on this screen.
      dirty = true;
      buttonsArm();
    }

    Button b = buttonsPoll();
    if (b != BTN_NONE) {
      if (saver) {
        saver = false;            // the waking press does nothing else
      } else if (b == BTN_YES) {
        coin = (coin + 1) % 3;    // YES: next coin
        verify = false;
      } else {
        verify = !verify;         // NO: QR <-> big text
      }
      lastInput = lastRotate = millis();
      dirty = true;
    }

    uint32_t idle = millis() - lastInput;
    if (!saver && idle > SAVER_IDLE_MS) {
      saver = true;
      verify = false;
      dirty = true;
    } else if (!saver && !verify && idle > ROTATE_IDLE_MS &&
               millis() - lastRotate > ROTATE_EVERY_MS) {
      coin = (coin + 1) % 3;
      lastRotate = millis();
      dirty = true;
    }

    if (dirty || millis() - lastDraw > REFRESH_MS) {
      if (saver) renderSaver(w);
      else if (verify) renderVerify(w, coin);
      else renderQr(w, coin);
      lastDraw = millis();
      dirty = false;
    }
    delay(5);
  }
}
