#ifndef SOTERIA_BUTTONS_H
#define SOTERIA_BUTTONS_H

#include <Arduino.h>

enum Button {
    BTN_NONE = 0,
    BTN_YES,
    BTN_NO,
};

// Debounced press detection for the two active-high buttons. A press
// only counts if its button was seen released after the last
// buttonsArm(), so a button still held from the previous screen can
// never answer the next prompt. Poll every few milliseconds.

// Start a new prompt/screen: buttons held right now must be released
// (and pressed again) before they register.
void buttonsArm();

// A new press since the last call (each press is reported once).
Button buttonsPoll();

#endif // SOTERIA_BUTTONS_H
