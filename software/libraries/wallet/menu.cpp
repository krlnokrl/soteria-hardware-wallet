#include "wallet.h"
void menu_pre(Adafruit_SSD1306 &display){
	display.clearDisplay();
	display.setTextColor(WHITE);
	display.setCursor(0, 0);
	display.setTextSize(1);
}

void menu_post(Adafruit_SSD1306 &display){
	display.display();
}
void menu_logo(Adafruit_SSD1306 &display, String name){
	
	menu_pre(display);
	
	displayLogo(display);
	
	String displayName;
	if(name != ""){
        displayName = (name) + " Wallet";
    }else{
        displayName = "Unnamed Wallet";
    }
	int16_t x1, y1;
    uint16_t w, h;
	display.getTextBounds(displayName, 0, 34, &x1, &y1, &w, &h);
	
	display.setCursor((display.width()-w)/2, 34);
	display.println(displayName);
	menu_post(display);
	
}

void menu_address(Adafruit_SSD1306 &display, char* address, String name){
	menu_pre(display);
	
	QRCode qrcode;
    uint8_t qrcodeData[qrcode_getBufferSize(3)];
	
    display.println(name);
	display.println("");
	for (int j = 0; j < 10; j++)
		display.print(address[j]);
	display.println('.');
	qrcode_initText(&qrcode, qrcodeData, 3, 1, address);
	displayQrCode(display, qrcode, 68);
	menu_post(display);
}

void menu_usb(Adafruit_SSD1306 &display){
	menu_pre(display);
	
	display.setTextSize(2);
	display.println("USB");
	display.setTextSize(1);
    display.println("Start USB comms?");
  
	menu_post(display);
}

void menu_usbConsole(Adafruit_SSD1306 &display, String commands[]){
	menu_pre(display);
	
	display.println("USB Console:\n");
	for(int i=0;i<5;i++){
		display.println(commands[i]);
	}
  
	menu_post(display);
}
void shuffle_insert(String commands[], String c){
	for(int i=4;i>0;i--){
		commands[i]=commands[i-1];
	}
	commands[0] = c;
}

