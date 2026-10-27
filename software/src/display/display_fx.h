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

// Draw at x = offset in 2x2 pixel modules; the caller calls display().
void displayQrCode(Adafruit_SSD1306 &display, QRCode &qrcode, uint8_t offset);

void displayYesNo(Adafruit_SSD1306 &display);
// Text in groups of 4 characters, 4 groups per line ("bc1q xy7k ..."),
// so an address can be compared group by group.
void displayGrouped(Adafruit_SSD1306 &display, const char *text);
#endif
