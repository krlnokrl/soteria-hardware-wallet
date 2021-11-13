#include <wallet.h>
//#include <WebUSB.h>
#include <qrcode.h>
#include <bip39.h>

#define YES 38
#define NO 2

//WebUSB WebUSBSerial(1 /* https:// */, "webusb.github.io/arduino/demos/console");

Adafruit_SSD1306 display(128, 64, &Wire, 4);

SecureStorage eeprom(0x50);

void setup() {
  SerialUSB.begin(9600);
  display.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  display.setRotation(2);
  display.clearDisplay();
  pinMode(YES, INPUT);
  pinMode(NO, INPUT);

}
void displayAddresses() {


}

void loop() {
  uint16_t feed = 0;
  eeprom.getFlag(6, feed);
  if (feed != GEN_FLAG) {
    display.setTextColor(WHITE);
    display.setCursor(5, 10);
    display.clearDisplay();
    display.setTextSize(1);
    display.print("No key found! \n Generate?");
    displayYesNo(display);
    display.display();
    while (!digitalRead(YES)) {
      delay(300);
    }
    display.setCursor(5, 10);
    generateWallet(display, eeprom);
  } else {
    QRCode qrcode;
    uint8_t qrcodeData[qrcode_getBufferSize(3)];
    int slot = 0;
    Key eth, btc, btct;
    String name;
    eeprom.getKey(0, btc);
    eeprom.getKey(1, eth);
    eeprom.getKey(2, btct);
    eeprom.getName(6, name);
    while (1) {
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
        display.println("BTC:");
        for (int j = 0; j < 9; j++)
          display.print(btc.publicKey[j]);
        display.println(".\n");
        display.print((100 - slot % 100) / 10);
        qrcode_initText(&qrcode, qrcodeData, 3, 1, btc.publicKey);
        displayQrCode(display, qrcode, 68);
      } else if (slot < 200) {
        display.println("ETH:");
        for (int j = 0; j < 9; j++)
          display.print(eth.publicKey[j]);
        display.println(".\n");
        display.print((100 - slot % 100) / 10);
        qrcode_initText(&qrcode, qrcodeData, 3, 1, eth.publicKey);
        displayQrCode(display, qrcode, 68);
      }
      else {
        display.println("BTCtest:");
        for (int j = 0; j < 9; j++)
          display.print(btct.publicKey[j]);
        display.println(".\n");
        display.print((100 - slot % 100) / 10);
        qrcode_initText(&qrcode, qrcodeData, 3, 1, btct.publicKey);
        displayQrCode(display, qrcode, 68);
      }
      display.setCursor(0, 0);
      slot = (slot + 1) % 300;
      delay(100);
      if (digitalRead(YES)) {
        display.clearDisplay();
        display.setCursor(0, 0);
        display.setTextSize(1);
        display.println("Start USB comm?");
        if (askYesNo(display)) {
          SerialUSB.begin(115200);
          while (!SerialUSB) {
            if (digitalRead(NO)) return;
            display.clearDisplay();
            display.setCursor(0, 0);
            display.print("Waiting for USB");
            display.display();
            delay(100);
          }
          SerialUSB.println("Connected ...");
          while (SerialUSB) {
            delay(100);
            display.clearDisplay();
            display.setCursor(0, 0);
            display.print("Communicating via USB");
            display.display();
            String data;
            if (SerialUSB.available()) {
              data = SerialUSB.readString();
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
                SerialUSB.print("BTC: "); SerialUSB.println(btc.publicKey);
                SerialUSB.print("ETH: "); SerialUSB.println(eth.publicKey);
                SerialUSB.print("BTCTest: "); SerialUSB.println(btct.publicKey);
              } else if ((getWordsInString(data, ' ', 0)) == "NAME") {
                if(name != ""){
                  SerialUSB.print("Name is alredy set: ");
                  SerialUSB.println(name);
                }else{
                  eeprom.writeName(6, getWordsInString(data, ' ', 1));
                  name = getWordsInString(data, ' ', 1);
                  SerialUSB.println(name);
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
