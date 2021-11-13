#ifndef __WALLET_H_
#define __WALLET_H_
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Wire.h>
#include <Bitcoin.h>
//#include <SecureIC.h>
#include <Hwallet.h>
//#include <ethers.h>
#include "display_fx.h"

#define GEN_FLAG 0xFEED

int RNGpin(uint8_t *dest, unsigned size);

void generateWallet(Adafruit_SSD1306 &display,SecureStorage &eeprom);

String getWordsInString(String data, char separator, int index);

boolean signEth(Adafruit_SSD1306 &display, String data, Key k);

boolean signBtc(Adafruit_SSD1306 &display, String data, Key k, boolean testnet);

void eraseDevice(Adafruit_SSD1306 &display, SecureStorage &eeprom);

void xorKey(Key &k, uint8_t *pin);

boolean askYesNo(Adafruit_SSD1306 &display);
char askXorY(Adafruit_SSD1306 &display, String x, String y);

void askPin(Adafruit_SSD1306 &display, uint8_t *pin);




void menu_logo(Adafruit_SSD1306 &display, String name);

void menu_address(Adafruit_SSD1306 &display, char* address, String name);

void menu_usb(Adafruit_SSD1306 &display);

void menu_usbConsole(Adafruit_SSD1306 &display, String commands[]);


void shuffle_insert(String commands[], String c);
#endif