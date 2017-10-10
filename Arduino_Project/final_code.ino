
#include <SPI.h>                                                                //Including Serial Peripheral Interface Library
#include <MFRC522.h>                                                            //Including MFRC522 Library for RFID Device

#include "EtherCard.h"                                                          //Including MFRC522 Library for RFID Device


// ethernet interface mac address, must be unique on the LAN
static byte mymac[] = { 0x74,0x69,0x69,0x2D,0x30,0x31 };                        // Assigning a Mac address to ENC28J60 module

const char website[] PROGMEM = "e-ist.esy.es";                                  //  host domain name
byte Ethernet::buffer[700];                                                    
static uint32_t timer;
bool status_value=false;

int running_status=0;   //This value indicates the running status ( 0 indicates not running and 1 indicates running )

byte reset=3;

// led pins 
int red_light=7;
int blue_light=6;
int green_light=5;

constexpr uint8_t RST_PIN = 4;     // Configurable, see typical pin layout above
constexpr uint8_t SS_PIN = 10;     // Configurable, see typical pin layout above

MFRC522 mfrc522(SS_PIN, RST_PIN);   // Create MFRC522 instance
MFRC522::MIFARE_Key key;
MFRC522::StatusCode status;

byte block;
byte len;


// This method is Called for each packet of returned data from the call to browseUrl (as persistent mode is set just before the call to browseUrl)

static void my_callback (byte status, word off, word len) 
{
  Serial.println(">>>");
  Ethernet::buffer[off+300] = 0;
  String data=(const char*) Ethernet::buffer + off;
  
  // parsing the received response from server
  
  int start_index=data.indexOf("@@@@")+4;
  int end_index=data.lastIndexOf("@@@@")-1;
  String response="";

  for(int i=start_index;i<=end_index;i++)
      response=response+data.charAt(i);

      Serial.println(response);
      status_value=true;
      running_status=0;  //running status 0 indicates that the current request is finished and device is read to accept new request
}




void setup () 
{
  Serial.begin(115200);
  SPI.begin();                                                  // Init SPI bus
  mfrc522.PCD_Init();                                           // Init MFRC522 card
  Serial.println(F("Read personal data on a MIFARE PICC:"));    //shows in serial that it is ready to read
  for (byte i = 0; i < 6; i++) key.keyByte[i] = 0xFF;
  
   //setting up 7 ,6 ,5 pins as output pins
    
   pinMode(red_light, OUTPUT);                              
   pinMode(blue_light,OUTPUT);
   pinMode(green_light,OUTPUT);
   pinMode(reset,OUTPUT);

   digitalWrite(red_light, HIGH);
   digitalWrite(blue_light, HIGH);
   digitalWrite(green_light, HIGH);
   
   delay(3000);


   //initializes the ethernet library and network settings
   
  if (ether.begin(sizeof Ethernet::buffer, mymac,8) == 0) 
  {
    //if any error occur red light will start blinking indicates that network error
    
    Serial.println( "Error:Ethercard.begin");
    digitalWrite(red_light, HIGH);
    digitalWrite(blue_light, LOW);
    digitalWrite(green_light, LOW);
    while(true);
  }
  

    //checks weather dhcp server allocated an ip or not
  if (!ether.dhcpSetup())
  {
    //if any error occur in generating IP red light will start blinking indicates that network error
    
    Serial.println("DHCP failed");
    digitalWrite(red_light, HIGH);
    digitalWrite(blue_light, LOW);
    digitalWrite(green_light, LOW);
    while(true);
  }
  
    ether.printIp("IP:  ", ether.myip);
    ether.printIp("GW:  ", ether.gwip);  
    ether.printIp("DNS: ", ether.dnsip); 


#if 0
  // Wait for link to become up - this speeds up the dnsLoopup in the current version of the Ethercard library
  while (!ether.isLinkUp())
  {
      ether.packetLoop(ether.packetReceive());
  }
  
#endif
  long t=millis();
  
  if (!ether.dnsLookup(website,false))
  {
      digitalWrite(red_light, HIGH);
      digitalWrite(blue_light, LOW);
      digitalWrite(green_light, LOW);
      Serial.println("DNS failed. Unable to continue.");
      while (true);
  }
  Serial.println(millis()-t);
  ether.printIp("SRV: ", ether.hisip);
  digitalWrite(red_light, LOW);
  digitalWrite(blue_light, HIGH);
  digitalWrite(green_light, LOW);
  digitalWrite(reset, LOW);
}



byte stop_condition=1;
byte timeout_error=1;


void loop () 
{
  if(timeout_error==0)
  ether.packetLoop(ether.packetReceive());


   if(stop_condition==0)
   {
     if(status_value==true)
      {
        Serial.println("data sent");
        stop_condition=1;
        //turn on green light
        digitalWrite(green_light, HIGH);
        delay(1500);
        digitalWrite(green_light,LOW);
        digitalWrite(blue_light,HIGH);
      }
      else if((millis()>timer)&&(!status_value==true))
      {
        Serial.println("time out error");
        stop_condition=1;
        timeout_error=1;
        running_status=0;
        digitalWrite(red_light, HIGH);
        delay(1500);
        digitalWrite(red_light,LOW);
        digitalWrite(blue_light,HIGH);
       }
     }

  //-------------------------------------------

  // Look for new cards
  if ( ! mfrc522.PICC_IsNewCardPresent()) {
    return;
  }

  // Select one of the cards
  if ( ! mfrc522.PICC_ReadCardSerial()) {
    return;
  }

  Serial.println(F("**Card Detected:**"));
  if(running_status==1)
    return;



  mfrc522.PICC_DumpDetailsToSerial(&(mfrc522.uid)); //dump some details about the card

  //mfrc522.PICC_DumpToSerial(&(mfrc522.uid));      //uncomment this to see all blocks in hex

  //-------------------------------------------

  Serial.print(F("Name: "));

  byte buffer1[18];

  block = 29;
  len = 18;

  //------------------------------------------- GET FIRST NAME
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, 29, &key, &(mfrc522.uid)); //line 834 of MFRC522.cpp file
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Authentication failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }

  status = mfrc522.MIFARE_Read(block, buffer1, &len);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("Reading failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }

String serial_data="";
  //PRINT FIRST NAME
  for (uint8_t i = 0; i < 16; i++)
  {
    if (buffer1[i] != 32)
    {
      Serial.write(buffer1[i]);
      
    }
  }
  serial_data=String((char *)buffer1);

  
  
  //if(Serial.available())
  //{
  
   //String serial_data=Serial.readString();
   if(serial_data.equals("reset"))
   {
     digitalWrite(reset,HIGH);
     pinMode(reset,OUTPUT);
     delay(200);
     digitalWrite(reset,LOW);
   }
    if(serial_data.length()==12)
    {
     digitalWrite(red_light, LOW);
     digitalWrite(blue_light, LOW);
     digitalWrite(green_light, LOW);
      
    make_request(serial_data);
    }
  //}
  
           

  //delay(1000); //change value if you want to read cards faster
  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();
}
void make_request(String data)
{
  running_status=1;
  status_value=false;
  stop_condition=0; 
   char a[13]= {'\0'};
 for (byte i=0; i<12; i++){
   a[i] = data.charAt(i);
}
timer=millis()+5000;
ether.browseUrl(PSTR("/studentdata.php?data="),a, website, my_callback);
Serial.print("<<< REQ ");
timeout_error=0;
}



