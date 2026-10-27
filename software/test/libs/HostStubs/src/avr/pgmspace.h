#pragma once
// Host stand-in: program memory is ordinary memory.
#include <string.h>
#define PROGMEM
#define memcpy_P memcpy
#define strcpy_P strcpy
