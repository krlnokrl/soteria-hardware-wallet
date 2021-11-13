#ifndef BIP39_H
#define BIP39_H

#include <inttypes.h>
#include <Arduino.h>

#include <stdbool.h>
#include <stdint.h>

#define BIP39_BUF_MAX 40

// This class provides a couple of services related to Bip39 mnemonic sentences
// First, it provides a way to look up english mnemonics by the code word that
// they represent.
// Next, it provides a means to generate a checksum on a sequence of bytes
// and then generate a series of words from that, or it provides you with
// a mechanism to input a sequence of words, verify the checksum and extract
// the original paylaod.

class Bip39 {
  private:
  char wordBuf[9];  
  char wordBufHi[9];

  uint16_t lo;
  uint16_t mid;
  uint16_t hi;
  
  uint8_t payloadBytes = 16;
  uint8_t payloadWords = 12;

  uint8_t buffer[BIP39_BUF_MAX];
  uint8_t *computeChecksum();

  uint8_t currentWord;
  void loadMnemonic(uint16_t i, char *b);
 public:
  Bip39() {}
  const char * getMnemonic(uint16_t n);
  void clear();

};
  String seedToWords(uint8_t *seed, int length);

#endif
