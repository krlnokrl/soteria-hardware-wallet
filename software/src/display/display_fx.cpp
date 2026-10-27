#include "display_fx.h"

void displaySandglass(Adafruit_SSD1306 &display)
{
	display.drawBitmap(
		(display.width()  - 15 ) / 2,
		0,
		sandglass, 15, 26, 1);

}

void displayLogo(Adafruit_SSD1306 &display)
{
	display.drawBitmap(
		(display.width()  - 32 ) / 2,
		0,
		logo, 32, 32, 1);
}
void displayProgressBar(Adafruit_SSD1306 &display)
{
	display.drawRect(10, 28, 100, 8, WHITE);
	  display.display();
}
void updateProgressBar(Adafruit_SSD1306 &display, uint8_t value)
{
	display.fillRect(10, 28, value, 8, WHITE);
	  display.display();
}

void displayQrCode(Adafruit_SSD1306 &display, QRCode &qrcode, uint8_t offset)
{
  int offsety = 1;
    for (uint8_t y = 0; y <qrcode.size; y++) {
        for (uint8_t x = 0; x <qrcode.size; x++) {
            if(qrcode_getModule(&qrcode, x, y))
            {
                display.drawPixel(offset+x*2, offsety+y*2, WHITE);
                display.drawPixel(offset+x*2+1, offsety+y*2, WHITE);
                display.drawPixel(offset+x*2, offsety+y*2+1, WHITE);
                display.drawPixel(offset+x*2+1, offsety+y*2+1, WHITE);
            }else{
                display.drawPixel(offset+x*2, offsety+y*2, BLACK);
                display.drawPixel(offset+x*2+1, offsety+y*2, BLACK);
                display.drawPixel(offset+x*2, offsety+y*2+1, BLACK);
                display.drawPixel(offset+x*2+1, offsety+y*2+1, BLACK);
            }
        }
    }
}

void displayYesNo(Adafruit_SSD1306 &display){
	display.setTextSize(1);
    display.setCursor(0,57);
	display.setTextColor(BLACK, WHITE);
	display.print(" No ");
	display.setCursor(95,57);
	display.print(" Yes ");
	display.setTextColor(WHITE);
}

void displayGrouped(Adafruit_SSD1306 &display, const char *text)
{
	for (int i = 0; text[i]; i++) {
		if (i > 0 && i % 16 == 0) display.println();
		else if (i > 0 && i % 4 == 0) display.print(' ');
		display.print(text[i]);
	}
	display.println();
}
