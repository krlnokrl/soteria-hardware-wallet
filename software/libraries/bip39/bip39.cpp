#include "bip39.h"
#include <avr/pgmspace.h>
#include <Arduino.h>
#include <Hash.h>

struct Bip39IndexChar {
    uint16_t i;
    char c;
};

//const
 Bip39IndexChar bip39_prefix1[] PROGMEM = {
#include "prefix1.h"
};

//const
 Bip39IndexChar bip39_prefix2[] PROGMEM = {
#include "prefix2.h"
};

#include "suffix_strings.h"

const char* const bip39_suffix[] PROGMEM = {
#include "suffix_array.h"
};

char 
bip39_lookup(Bip39IndexChar *table, uint8_t length, uint16_t n) {
  uint8_t lo = 0;
  uint8_t hi = length;
  uint8_t mid;
  static Bip39IndexChar m;

  while(lo+1 < hi) {
    mid = (lo + hi) /2;
    memcpy_P(&m, &(table[mid]), sizeof (Bip39IndexChar));
    if(m.i < n) {
        lo = mid;
    } else if (m.i> n) {
        hi = mid;
    } else {
        lo = mid;
        break;
    }
  } 
  memcpy_P (&m, &table[lo], sizeof (Bip39IndexChar));
  return m.c;
}

void
Bip39::loadMnemonic(uint16_t i, char *b)
{
  b[0] = bip39_lookup(bip39_prefix1, PREFIX_1_LEN_BIP39, i);    
  b[1] = bip39_lookup(bip39_prefix2, PREFIX_2_LEN_BIP39, i);    
  strcpy_P(b + 2, (bip39_suffix[i])); // Necessary casts and dereferencing, just copy.
}

const char *
Bip39::getMnemonic(uint16_t i) {
  loadMnemonic(i, wordBuf);
  return wordBuf;
}

String seedToWords(uint8_t *seed, int length)
{
	Bip39 b;
	//SHA256 sha256;
	String words;
	uint8_t size = length*8 + length/4;
	boolean ent[size];
	uint8_t x=0;
	
	for(int i=0; x<length*8 ;i++)
	{
		for(int j=7;j>=0;j--){
			ent[x++] = bitRead(seed[i], j);
		}
	}
	
	uint8_t hash[32];
	//sha256.reset();
	//sha256
	sha256(seed,length,hash);
	//sha256.finalize(hash,32);
	for(int j=7;j>=length/4;j--){
		ent[x++] = bitRead(hash[0], j);
	}
	
	for(int i=0;i<size;){
		uint16_t w = 1;
		for(int j=10;j>=0;j--)
		{
			w=w*2+ent[i++];
		}  
		w=w%2048;
		words = words + (b.getMnemonic(w)) + " ";
		
	}
	return words;
}




