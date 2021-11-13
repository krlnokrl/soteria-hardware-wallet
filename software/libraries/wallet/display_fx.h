#ifndef __DISPLAYFX_H_
#define __DISPLAYFX_H_

#include "sandglass.h"
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <qrcode.h>

void displaySandglass(Adafruit_SSD1306 &display);
void displayLogo(Adafruit_SSD1306 &display);
void displayProgressBar(Adafruit_SSD1306 &display);
void updateProgressBar(Adafruit_SSD1306 &display, uint8_t value);

void displayQrCode(Adafruit_SSD1306 &display, QRCode &qrcode, uint8_t offset);

void displayYesNo(Adafruit_SSD1306 &display);
void displayXorY(Adafruit_SSD1306 &display, String x, String y);
#endif
