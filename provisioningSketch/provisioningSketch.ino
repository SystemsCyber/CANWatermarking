/*
 * CAN Watermarking Device Sketch
 * 
 * Arduino Sketch for provisioning a Teensy 4.0 equipped device by sending the device serial 
 * number and exchanging public keys along with their signatures with the 
 * Amazon Web Services server
 * 
 * Written By Duy Van
 * Colorado State University
 * Department of Systems Engineering
 * 
 * 3 March 2020
 * 
 * Released under the MIT License
 *
 * Copyright (c) 2020        Jeremy S. Daily, Duy Van
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * 
 */
#include <Arduino.h>
#include <i2c_driver_wire.h>
// This is a heavily modified library:
#include <SparkFun_ATECCX08a_Arduino_Library.h> 

#define RED_LED    3
#define GREEN_LED  2
#define YELLOW_LED 4
#define AMBER_LED  5 

ATECCX08A atecc;

// A buffer to get data into the ATECC EEPROM
uint8_t temp_buf[32];
// A buffer for the X962 encoded UncompressedPoint formatted SECP256R1 ECC public key (less the leading byte of 0x04).
uint8_t server_public_key[64];
// A buffer for an AES encrypted password
uint8_t encrypted_pass[16];
// A buffer for the DER encoded PKCS1 formatted 2048 RSA public key
uint8_t server_rsa_key[270];
// A buffer to accept serial commands
String serial_string;

void setup() {
  pinMode(RED_LED,OUTPUT);
  pinMode(GREEN_LED,OUTPUT);
  pinMode(YELLOW_LED,OUTPUT);
  pinMode(AMBER_LED,OUTPUT);
  pinMode(LED_BUILTIN,OUTPUT);
   
  Serial.begin(9600);
  //Initiate ATECC608A connection
  Wire.begin();
  if (atecc.begin() == true)
  {
    Serial.println("Success connecting to the ATECC608A");
    digitalWrite(LED_BUILTIN,HIGH);
  }
  else
  {
    Serial.println("Device not found. Check wiring.");
    while (1){ // stall out forever
      digitalWrite(YELLOW_LED,HIGH);
      digitalWrite(RED_LED,LOW);
      digitalWrite(GREEN_LED,HIGH);
      digitalWrite(AMBER_LED,LOW);
      delay(100);
      digitalWrite(GREEN_LED,LOW);
      digitalWrite(AMBER_LED,HIGH);
      digitalWrite(YELLOW_LED,LOW);
      digitalWrite(RED_LED,HIGH);
      delay(100);
    }
  }  
}

void loop() { 
  //Wait for serial communications to initiate the commands
  while(Serial.available() == 0);//wait for Python input
  serial_string = Serial.readStringUntil('\n');

  if (serial_string.equalsIgnoreCase("KEY")) 
  { // Create and lock a private ECC key. Send the public key
    atecc.writeProvisionConfig(); //Write and Lock Configuration made specifically for the CAN Logger 3 application, please see library for more detail
    atecc.lockConfig(); //Lock Configuration zone
    atecc.createNewKeyPair(); //Create ECC key pair on slot 0
    atecc.lockDataSlot(0); //Lock private key on slot 0
    // Sends serial number and an ECC public key.  
    atecc.readConfigZone(false); // produces a serial number
    atecc.generatePublicKey(0,false); //compute public key from slot 0 private key
    
    //Send serial number to python through local serial
    for (int n = 0; n < sizeof(atecc.serialNumber);n++){
      char hex_digit[3];
      sprintf(hex_digit,"%02X",atecc.serialNumber[n]);
      Serial.write(hex_digit);
    }
    Serial.write('\n');  
    //Send device public key to python through local serial
    for (int n = 0; n < sizeof(atecc.publicKey64Bytes);n++){
      char hex_digit[3];
      sprintf(hex_digit,"%02X",atecc.publicKey64Bytes[n]);
      Serial.write(hex_digit);
    }
    digitalWrite(AMBER_LED,HIGH); 
  }
  
  else if (serial_string.equalsIgnoreCase("ECC"))
  { //Wait for server to send its public key
    while (Serial.available() == 0);//wait for serial input again
    for (int i = 0; i < sizeof(server_public_key); i++){
      byte c = Serial.read();
      server_public_key[i] = c;
    }
    //Load the received public key to slot 10 on the ATECC
    atecc.loadPublicKey(server_public_key,false); 
    digitalWrite(YELLOW_LED,HIGH);
  }
  
  else if (serial_string.equalsIgnoreCase("RSA")){
    //Wait for server to send its  RSA public key
    while (Serial.available() == 0);//wait for Python input again
    for (int i = 0; i < sizeof(server_rsa_key); i++){
      byte c = Serial.read();
      server_rsa_key[i] = c;
    }
    for (int i = 0; i < sizeof(server_rsa_key); i += sizeof(temp_buf)){
      memcpy(&temp_buf[0],&server_rsa_key[0],sizeof(temp_buf));
      if(atecc.write(ZONE_DATA, ADDRESS_DATA_SLOT8_BLOCK_0+i, temp_buf, sizeof(temp_buf))){
        digitalWrite(RED_LED,HIGH);
      }
    }
    
  }

  else if (serial_string.equalsIgnoreCase("LOCK")){
    atecc.lockDataAndOTP(); //Lock Data and OTP zone in order to read the server public key later for ECDH
    atecc.readPublicKey(false);//Read the stored server public key
    for (int j =0;j<sizeof(atecc.storedPublicKey);j++){
      char hex_digit[3];
      sprintf(hex_digit,"%02X", atecc.storedPublicKey[j]);
      Serial.print(hex_digit);
    }
    digitalWrite(GREEN_LED,HIGH);
  }

  else if (serial_string.equalsIgnoreCase("GETRSA")){
    atecc.readRSAKey(false);//Read the stored server public key
    for (int j =0;j<sizeof(atecc.storedRSAKey);j++){
      char hex_digit[3];
      sprintf(hex_digit,"%02X", atecc.storedRSAKey[j]);
      Serial.print(hex_digit);
    }
  }

  
  
  else if (serial_string.equalsIgnoreCase("PASSWORD")) 
  { //Decrypt password process to test provisioning.
    while (Serial.available() == 0);//wait for serial input again
    for (int i = 0; i < sizeof(encrypted_pass); i++){
      byte c = Serial.read();
      encrypted_pass[i] = c;
    }      
    atecc.readPublicKey(false);
    atecc.ECDH(atecc.storedPublicKey, ECDH_OUTPUT_IN_TEMPKEY,0x0000);
    atecc.AES_ECB_decrypt(encrypted_pass);
    for (int n = 0; n < sizeof(atecc.AES_buffer); n++){
      char hex_digit[3];
      sprintf(hex_digit,"%02X",atecc.AES_buffer[n]);
      Serial.write(hex_digit);
    }
    for (int i = 1;i<5;i++){
      digitalWrite(RED_LED,LOW);
      digitalWrite(YELLOW_LED,LOW);
      delay(100);
      digitalWrite(YELLOW_LED,HIGH);
      digitalWrite(RED_LED,HIGH);
      delay(100);
    };
  }
}
