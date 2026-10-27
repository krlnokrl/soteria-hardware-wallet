#pragma once
// Host stand-in for the OLED driver: accepts and ignores drawing calls.
#include <Arduino.h>
#define WHITE 1
#define BLACK 0
class Adafruit_SSD1306 {
public:
    void clearDisplay() {}
    void setTextColor(int, int = 0) {}
    void setTextSize(int) {}
    void setCursor(int, int) {}
    void print(const char *) {}
    void print(char) {}
    void println(const char * = "") {}
    void display() {}
};
