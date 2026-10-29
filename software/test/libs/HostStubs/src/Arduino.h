#pragma once
// Host stand-in for the Arduino core (see HostStubs.cpp).
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>

typedef std::string String;
typedef bool boolean;
typedef uint8_t byte;

#define HIGH 1
#define LOW 0
#define INPUT 0
#define bitRead(value, bit) (((value) >> (bit)) & 0x01)

uint32_t millis();
uint32_t micros();
void delay(uint32_t ms);
void delayMicroseconds(uint32_t us);
int digitalRead(int pin);
int analogRead(int pin);
