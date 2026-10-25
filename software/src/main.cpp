#include <Arduino.h>
#include <wallet.h>
#include "utils.h"
#include <qrcode.h>
#include "u2f.h"

#define YES 38
#define NO 2

//WebUSB WebUSBSerial(1 /* https:// */, "webusb.github.io/arduino/demos/console");

Adafruit_SSD1306 display(128, 64, &Wire, 4);

SecureStorage eeprom(0x50);

void setup() {
  Serial.begin(9600);
  Wire.begin();
  display.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  display.setRotation(2);
  display.clearDisplay();
  pinMode(YES, INPUT);
  pinMode(NO, INPUT);

  gU2F.begin();   // initialise the USB HID / CTAPHID U2F interface
}
void displayAddresses() {

}

void loop() {
  gU2F.poll();   // service USB HID / CTAPHID U2F requests

  uint16_t feed = 0;
  eeprom.getFlag(6, feed);
  if (feed != GEN_FLAG) {
    display.setTextColor(WHITE);
    display.setCursor(5, 10);
    display.clearDisplay();
    display.setTextSize(1);
    display.print("No key found!\n Generate?");
    displayYesNo(display);
    display.display();
    while (!digitalRead(YES)) {
      gU2F.poll();   // keep servicing USB HID while we wait for the button
      delay(300);
    }
    generateWallet(display, eeprom);
  } else {
    Key eth, btc, btct;
    String name;
    eeprom.getKey(0, btc);
    eeprom.getKey(1, eth);
    eeprom.getKey(2, btct);
    eeprom.getName(6, name);
    int slot = 0;
    while (1) {
      gU2F.poll();   // this loop never returns to loop(); service USB here too
      display.clearDisplay();
      display.setCursor(0, 0);
      display.setTextColor(WHITE);
      display.setTextSize(1);
      if(name != ""){
        display.print(name);
        display.println("\nWallet\n");
      }else{
        display.println("Unnamed\nWallet\n");
      }
      if (slot < 100) {
        String addr = keyAddress(btc, false);
        display.println("BTC:");
        display.print(addr);
        display.println("\n");
        QRCode qrcode;
        uint8_t qrcodeData[qrcode_getBufferSize(3)];
        qrcode_initText(&qrcode, qrcodeData, 3, 1, addr.c_str());
        displayQrCode(display, qrcode, 68);
      } else if (slot < 200) {
        String addr = keyAddress(btct, true);
        display.println("BTCtest:");
        display.print(addr);
        display.println("\n");
        QRCode qrcode;
        uint8_t qrcodeData[qrcode_getBufferSize(3)];
        qrcode_initText(&qrcode, qrcodeData, 3, 1, addr.c_str());
        displayQrCode(display, qrcode, 68);
      } else {
        char ethAddr[43];
        ethAddressFromKey(eth, ethAddr);
        String ethAddrStr(ethAddr);
        display.println("ETH:");
        // Address is 42 chars; show checksummed form and QR it in full.
        display.println(ethAddrStr);
        display.println("\n");
        QRCode qrcode;
        uint8_t qrcodeData[qrcode_getBufferSize(3)];
        qrcode_initText(&qrcode, qrcodeData, 3, 1, ethAddr);
        displayQrCode(display, qrcode, 68);
      }
      slot = (slot + 1) % 300;
      delay(100);
      if (digitalRead(YES)) {
        display.clearDisplay();
        display.setCursor(0, 0);
        display.setTextSize(1);
        display.println("Start USB comm?");
        if (askYesNo(display)) {
          Serial.begin(115200);
          while (!Serial) {
            if (digitalRead(NO)) return;
            display.clearDisplay();
            display.setCursor(0, 0);
            display.print("Waiting for USB");
            display.display();
            delay(100);
          }
          Serial.println("Connected ...");
          while (Serial) {
            gU2F.poll();   // USB HID keeps working while the serial console is open
            delay(100);
            display.clearDisplay();
            display.setCursor(0, 0);
            display.print("Communicating via USB");
            display.display();
            String data;
            if (Serial.available()) {
              data = Serial.readString();
              data.toUpperCase();
              if ((getWordsInString(data, ' ', 0)) == "SIGN") {
                if ((getWordsInString(data, ' ', 1)) == "ETH") {
                  signEth(display, getWordsInString(data, ' ', 2), eth);
                } else if ((getWordsInString(data, ' ', 1)) == "BTCT") {
                  signBtc(display, getWordsInString(data, ' ', 2), btct, true);
                } else if ((getWordsInString(data, ' ', 1)) == "BTC") {
                  signBtc(display, getWordsInString(data, ' ', 2), btc, false);
                }
              } else if ((getWordsInString(data, ' ', 0)) == "ERASE") {
                eraseDevice(display, eeprom);
                return;
              } else if ((getWordsInString(data, ' ', 0)) == "ADDRESS") {
                Serial.print("BTC: "); Serial.println(keyAddress(btc, false));
                Serial.print("BTCTest: "); Serial.println(keyAddress(btct, true));
                char ethAddr[43];
                ethAddressFromKey(eth, ethAddr);
                Serial.print("ETH: "); Serial.println(ethAddr);
              } else if ((getWordsInString(data, ' ', 0)) == "NAME") {
                if(name != ""){
                  Serial.print("Name is alredy set: ");
                  Serial.println(name);
                }else{
                  eeprom.writeName(6, getWordsInString(data, ' ', 1).c_str());
                  name = getWordsInString(data, ' ', 1);
                  Serial.println(name);
                }
              }
            }
          }
        }
      }
    }
  }

  delay(3000);
}
