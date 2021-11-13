#include "wallet.h"
#include <bip39.h>
#define YES 38
#define NO 2

String getWordsInString(String data, char separator, int index)
{
  int maxIndex = data.length() - 1;
  int j = 0;
  String chunkVal = "";

  for (int i = 0; i <= maxIndex && j <= index; i++)
  {
    chunkVal.concat(data[i]);

    if (data[i] == separator)
    {
      j++;

      if (j > index)
      {
        chunkVal.trim();
        return chunkVal;
      }

      chunkVal = "";
    }
    else if ((i == maxIndex) && (j < index)) {
      chunkVal = "";
      return chunkVal;
    }
  }
}


int RNGpin(uint8_t *dest, unsigned size) {
  // Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of
  // random noise). This can take a long time to generate random data if the result of analogRead(0)
  // doesn't change very frequently.
  while (size) {
    uint8_t val = 0;
    for (unsigned i = 0; i < 8; ++i) {
      int init = analogRead(0);
      int red = analogRead(1) & 0x01;
      int count = 0;
      while (analogRead(0) == init) {
        ++count;
      }

      if (count == 0) {
		init += red;
        val = (val << 1) | (init & 0x01);
      } else {
        count += red;
        val = (val << 1) | (count & 0x01);
      }
    }
    *dest = val;
    ++dest;
    --size;
  }
  // NOTE: it would be a good idea to hash the resulting random data using SHA-256 or similar.
  return 1;
}

void generateWallet(Adafruit_SSD1306 &display,SecureStorage &eeprom)
{
  uint8_t pin[5];
  uint8_t pin1[5];
  uint8_t seed[32];
  Bip39 bip39;

  askPin(display, pin);
  display.setCursor(15, 0);
  display.print("Input pin again to verify");
  display.display();
  delay(2000);
  askPin(display, pin1);
  display.setCursor(15, 0);
  for(int i=0; i<5;i++)
	  if(pin[i]!=pin1[i]){  
		display.print("Pins do not match!");
		display.display();
		delay(2000);
		return;
	  }
  display.clearDisplay();
  displaySandglass(display);
  displayProgressBar(display);
  display.display();
  
  RNGpin(seed, 32);
  sha256(seed, 32, seed);
  display.setTextSize(1);
  display.setCursor(0, 0);
  updateProgressBar(display,5);
  display.display();
  
  HDPrivateKey hdKey;
  String s = seedToWords(seed, 16); 
  char mnem[200];
  s.toCharArray(mnem, s.length());
  updateProgressBar(display,30);
  display.display();
  char pass[1];
  hdKey.fromMnemonic(mnem, s.length(), pass, 0); 
  updateProgressBar(display,40);
  display.display();
  HDPrivateKey btcKey = hdKey.hardenedChild(44).hardenedChild(0).hardenedChild(0).child(0).child(0);
  HDPrivateKey btctKey = hdKey.hardenedChild(44).hardenedChild(1).hardenedChild(0).child(0).child(0);
  HDPrivateKey ethKey = hdKey.hardenedChild(44).hardenedChild(60).hardenedChild(0).child(0).child(0);
  HDPrivateKey u2fKey = hdKey.hardenedChild(44).hardenedChild(99).hardenedChild(0).child(0).child(0);
  updateProgressBar(display,60);
  display.display();
  
  Key k;
  
  k.network = BTC;
  k.id = 0;
  k.nonce = 0;
  btcKey.privateKey.getSecret(k.privateKey);
  btcKey.privateKey.address(k.publicKey, 43);
  xorKey(k, pin);
  eeprom.storeKey(0, k);
  updateProgressBar(display,70);
  display.display();
  
  
  k.network = BTC;
  k.id = 2;
  k.nonce = 0;
  btctKey.privateKey.testnet = true;
  btctKey.privateKey.getSecret(k.privateKey);
  btctKey.privateKey.address(k.publicKey, 43);
  xorKey(k, pin);
  eeprom.storeKey(2, k);
  updateProgressBar(display,80);
  display.display();
  
  k.network = U2F;
  k.id = 3;
  k.nonce = 0;
  u2fKey.privateKey.getSecret(k.privateKey);
  k.publicKey;
  xorKey(k, pin);
  eeprom.storeKey(3, k);
  updateProgressBar(display,90);
  display.display();
  
  k.network = ETH;
  k.id = 1;
  k.nonce = 0;
  ethKey.privateKey.getSecret(k.privateKey);
  ethers_privateKeyToChecksumAddress(k.privateKey, k.publicKey);
  xorKey(k, pin);
  eeprom.storeKey(1, k);
  updateProgressBar(display,100);
  display.display();
  
  
  for (int q = 0 ; q < 2; q++){
    for (int i = 0; i < 12; i++)
    {
		display.clearDisplay();
		display.setCursor(15, 0);
		display.setTextSize(1);
        if(q==0)
        {
          display.print("Write");
        }else{
          display.print("Verify");
        }
        display.setTextSize(2);
        display.setCursor(0, 20);
        display.print(i + 1);
        display.print(":");
        display.println(getWordsInString(s, ' ', i));
        display.display();
		delay(1000);
		displayYesNo(display);
        display.display();
		while(!digitalRead(YES))
		{
			delay(300);
		}
    }
  }

    uint16_t flag = GEN_FLAG;
    eeprom.writeFlag((unsigned char)6, flag);
}

void xorKey(Key &k, uint8_t *pin){
	uint8_t hash[32];
	sha256(pin, 5, hash);
	for(int i=0; i<32;i++)
	{
		k.privateKey[i] = k.privateKey[i] ^ hash[i];
	}
}

void askPin(Adafruit_SSD1306 &display, uint8_t *pin){
  display.clearDisplay();
  display.setCursor(15, 0);
  display.setTextColor(WHITE);
  display.println("Input pin");
  display.display();
  int num = analogRead(A7)/64;
  for(char i=0; i<5;)
  {
	  delay(300);
	  while(!digitalRead(YES)){
		  num = analogRead(A7)/64;
		  display.clearDisplay();
		   display.setTextSize(1);
		display.setCursor(15, 0);
		  display.println("Input pin\n\n");
		display.setTextSize(3);
		  for(char v =0; v<5;v++){
			  if(v==i){
				  display.print(num, HEX);
				}else{display.print("*");}
			}
		if(digitalRead(NO)){
			return;
		}
		displayYesNo(display);
		display.display();
		delay(300);
	  }
	  pin[i++] = num;
	display.display();
  }
  for(int i=3; i>=1; i--){
  display.setCursor(0, 0);
  display.clearDisplay();
  display.print(i, DEC);
  display.display();
  display.clearDisplay();
  delay(500);
  }
}
boolean askYesNo(Adafruit_SSD1306 &display){
	delay(500);
	displayYesNo(display);
    display.display();
    display.clearDisplay();
    display.setCursor(0, 0);
	while(true) {
       if (digitalRead(NO)) {
          return false;
        }
		if (digitalRead(YES)) {
          return true;
        }
        delay(500);
    }
	return true;
}

char askXorY(Adafruit_SSD1306 &display, String x, String y){
	delay(500);
	displayXorY(display, x, y);
	while(true) {
       if (digitalRead(NO)) {
          return 'X';
        }
		if (digitalRead(YES)) {
          return 'Y';
        }
        delay(200);
    }
	return 'N';
	
	
}

boolean signBtc(Adafruit_SSD1306 &display, String data, Key k, boolean testnet){
  char hex[data.length()];
  byte raw[data.length()/2];
  data.toCharArray(hex, data.length());
  size_t len = fromHex(hex, raw, sizeof(raw));
  Transaction tx;
  size_t cur = tx.parse(raw, len);
  
  uint8_t pin[5];
  
  display.clearDisplay();
    display.setCursor(0, 0);
    display.setTextSize(1);
    display.println("Sign BTC Transaction?");
	float total = 0;
	for (int i = 0; i < tx.outputsNumber; i++) {
		total += ((float)tx.txOuts[i].amount) / 100000.0;
	}
	display.print("Ins:"); display.print(tx.inputsNumber);
	display.print("-Outs:"); display.print(tx.inputsNumber);
	display.print(" T:"); display.print(total, 1); display.println("m"); 
	for (int i = 0; i < tx.outputsNumber; i++) {
		for(int x=0;x<10;x++){
			display.print(tx.txOuts[i].address(testnet)[x]);
		}
		display.print(".:");
		display.print(((float)tx.txOuts[i].amount) / 100000.0);
		display.println("mBTC");
	}
	display.display();
	if(askYesNo(display)){
		askPin(display, pin);
		xorKey(k, pin);
		PrivateKey pk(k.privateKey);
		SerialUSB.println(pk.publicKey().address(true));
		SerialUSB.println(pk.publicKey().address(false));
		for(int i=0; i<tx.inputsNumber; i++){
			Signature sig = tx.signInput(i, k.privateKey);
		}
		SerialUSB.println(tx);
		return true;
	}
	return false;
	
  
}

boolean signEth(Adafruit_SSD1306 &display, String data, Key k){
	ETHTransaction transaction;
	uint8_t hash[32];
	uint8_t pin[5];
	boolean dec = ethers_parseTransaction(&transaction, hash, data);
	display.clearDisplay();
    display.setCursor(0, 0);
    display.setTextSize(1);
	if(!dec){
		display.println("Invalid Transaction");
		display.display();
		delay(1000);
		display.clearDisplay();
		return false;
	}
    display.println("Sign ETH Transaction?");
    display.print("Nonce: ");
    display.println(transaction.nonce, DEC);
    display.print("Data Length: ");
    display.println(transaction.dataLength, DEC);
	/*  For unsigned transactions V is the chain id 
		For signed ones V becomes chainid*2 + 35		*/
    display.print("Chain Id: ");
	if(transaction.chainId == 1){
		display.print("MAIN ");
	}else if(transaction.chainId == 3){
		display.print("ROP ");
	}else if(transaction.chainId == 61){
		display.print("ETC ");
	}
    display.println(transaction.chainId, DEC);
    display.print("TO:");
	char to_address[43];
	ethers_addressToChecksumAddress(transaction.address, to_address);
	for(int i=0;i<13;i++)
		display.print(to_address[i]);
    display.println(".");
    display.print("ETH ");
    ethers_toString(transaction.value, transaction.valueLength, (18 - 5), (char*)transaction.data);
    display.println((char*)transaction.data);
    display.display();
	if(askYesNo(display)){
		display.clearDisplay();
		askPin(display, pin);
		xorKey(k, pin);
		PrivateKey pk(k.privateKey);
        Signature sig =  pk.sign(hash);
		display.println("R and S:");
        SerialUSB.println("R:" + toBase58(sig.r, 32));
		SerialUSB.println("R:" + toHex(sig.r, 32));
		SerialUSB.println("*");
        SerialUSB.println("S:" + toBase58(sig.s, 32));
        SerialUSB.println("S:" + toHex(sig.s, 32));
		SerialUSB.println("--------");
        QRCode qrcodeR;
        uint8_t qrcodeDataR[qrcode_getBufferSize(3)];
        QRCode qrcodeS;
        uint8_t qrcodeDataS[qrcode_getBufferSize(3)];
        qrcode_initText(&qrcodeR, qrcodeDataR, 3, 0, ("R:" + toBase58(sig.r, 32)).c_str());
        displayQrCode(display, qrcodeR, 0);
        qrcode_initText(&qrcodeS, qrcodeDataS, 3, 0, ("S:" + toBase58(sig.s, 32)).c_str());
        displayQrCode(display, qrcodeS, 64);
		display.display();
		
		delay(4000);
		while (!digitalRead(YES)) {
            delay(200);
        }
		return true;
	}
	return false;
}

void eraseDevice(Adafruit_SSD1306 &display, SecureStorage &eeprom){
	display.clearDisplay();
    display.setCursor(0, 0);
    display.setTextSize(2);
    display.println("!!ERASE!!");
    display.setTextSize(1);
    display.println("\nAll keys will be lost forever!");
    display.display();
    delay(2000);
	if(askYesNo(display)){
		display.setTextSize(1);
		display.println("Are you sure you want to erase?");
		display.display();
		if(askYesNo(display)){
			uint16_t flag = 0xFFFF;
          eeprom.writeFlag(6, flag);
          Key k;
          memset(k.privateKey, 0xFFFF, 32);
          memset(k.publicKey, 0xFFFF, 20);
          for (int i = 0; i < 6; i++)
          {
            eeprom.storeKey(i, k);
          }
		  char name[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
		  eeprom.writeName(6, name);
          display.println("DONE!");
          display.display();
		  delay(1000);
		}
	}
	
}
