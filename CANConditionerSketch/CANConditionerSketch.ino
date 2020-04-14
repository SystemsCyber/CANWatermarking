#define SELF_SOURCE_ADDR  136
#include <SparkFun_ATECCX08a_Arduino_Library.h> 
#include "SecureJ1939.h"

#define RED_LED    3
#define GREEN_LED  2
#define YELLOW_LED 4
#define AMBER_LED  5 

ATECCX08A atecc;

byte init_vector[16];
byte aes_key[16];
byte encrypted_key[16];

CAN_message_t vehicle_msg;
CAN_message_t ecu_msg;


boolean RED_LED_state;
boolean GREEN_LED_state;
boolean YELLOW_LED_state;
boolean AMBER_LED_state;

uint32_t TXcount;
uint32_t vehicle_rx_count;
uint32_t ecu_rx_count;
boolean new_block = false;

elapsedMillis vehicle_rx_timer;
elapsedMillis ecu_rx_timer;

void atecc_error_flash(){
  while (1){
      //Setup Blinking pattern
      digitalWrite(AMBER_LED,LOW);
      digitalWrite(RED_LED,HIGH);
      delay(200);
      digitalWrite(YELLOW_LED,LOW);
      digitalWrite(GREEN_LED,HIGH);
      delay(200);
      digitalWrite(RED_LED,LOW);
      digitalWrite(AMBER_LED,HIGH);
      delay(200);
      digitalWrite(YELLOW_LED,HIGH);
      digitalWrite(GREEN_LED,LOW);
      delay(200);
    }
}

void setup(void) {
  vehicle_can.begin();
  vehicle_can.setBaudRate(250000);
  ecu_can.begin();
  ecu_can.setBaudRate(250000);
  
  Serial5.begin(9600);
  pinMode(RED_LED,OUTPUT);
  pinMode(GREEN_LED,OUTPUT);
  pinMode(YELLOW_LED,OUTPUT);
  pinMode(AMBER_LED,OUTPUT);
  pinMode(LED_BUILTIN,OUTPUT);
  RED_LED_state = true;
  
  Wire.begin();
  if (atecc.begin() == true)
  {
    Serial.println("Successful wakeUp(). I2C connections are good.");
  }
  else
  {
    Serial.println("Device not found. Check wiring.");
    atecc_error_flash();
  }

  atecc.readConfigZone(false); // Debug argument false (OFF)
  
  Serial.print("Serial Number: \t");
  print_bytes(atecc.serialNumber, sizeof(atecc.serialNumber));
  for (int i = 0; i<sizeof(atecc.serialNumber); i++){
    if (2*i >= sizeof(serial_string)) break; // Be sure not to overflow theserial strin buffer
    char hex_char[3];
    sprintf(hex_char,"%02X",atecc.serialNumber[i]);
    memcpy(&serial_string[2*i],&hex_char,2);
  }
  sprintf(model_string,"CANConditioner");
  
  Serial.print("Config Zone: \t");
  if (atecc.configLockStatus) Serial.println("Locked");
  else Serial.println("NOT Locked");

  Serial.print("Data/OTP Zone: \t");
  if (atecc.dataOTPLockStatus) Serial.println("Locked");
  else Serial.println("NOT Locked");

  Serial.print("Data Slot 0: \t");
  if (atecc.slot0LockStatus) Serial.println("Locked");
  else Serial.println("NOT Locked");

  // if everything is locked up, then configuration is complete, so let's print the public key
  if (atecc.configLockStatus && atecc.dataOTPLockStatus && atecc.slot0LockStatus) 
  {
    if(atecc.generatePublicKey(0) == false)
    {
      Serial.println("Failure to generate this device's Public Key");
      Serial.println();
    }
  }
  else
  { 
    Serial.println("ATECC not Locked. Please provision correctly.");
    atecc_error_flash(); // stall out forever
  }
  
  atecc.updateRandom32Bytes();
  memcpy(&aes_key[0],&atecc.random32Bytes[0],sizeof(aes_key));
  memcpy(&init_vector[0],&atecc.random32Bytes[sizeof(aes_key)],sizeof(init_vector));
  
  Serial.println("Plain AES Session Key: ");
  print_bytes(aes_key, sizeof(aes_key));

  memcpy(own_public_key,atecc.publicKey64Bytes,sizeof(own_public_key));
  Serial.println("Own Public Key: ");
  print_bytes(own_public_key, sizeof(own_public_key));

  // Get Gateway Public Key
  
  uint8_t gateway_sa = 37;
  uint8_t sa_index = get_sa_index(gateway_sa);
  bool received_public_key = false;
  elapsedMillis wait_timer;
  while (received_public_key == false){
    if (wait_timer >= 2000){
      wait_timer = 0;
      send_public_key(gateway_sa);
    }
    if (vehicle_can.read(vehicle_msg)){
      int num_bytes = parseJ1939(vehicle_msg);
      if (num_bytes > 8){
        Serial.println("RX transport message:");
        Serial.printf("PGN: %04X, SA: %02X, DA: %02X, DLC: %d, Data: ", j1939_pgn, j1939_sa, j1939_da, num_bytes);
        print_bytes(j1939_data, num_bytes);
        if (j1939_pgn == DM18_PGN){
          Serial.println("Data Security Message Found.");
          uint8_t msg_len = j1939_data[0];
          uint8_t msg_type = j1939_data[1];
          if (msg_type == DM18_PUBLIC_KEY_TYPE && msg_len == 64 ){
            Serial.println("Setting device_public_key memory.");
            memcpy(&device_public_key[sa_index][0],&j1939_data[2],msg_len);
            atecc.ECDH(device_public_key[sa_index], ECDH_OUTPUT_IN_TEMPKEY,0x0000);
            atecc.AES_ECB_encrypt(aes_key); // This loads the key into the AES_buffer
            setup_aes_key(sa_index, init_vector, aes_key);
            received_public_key = true;
            break;
          }
        }
      }   
    }
  }
  atecc.ECDH(device_public_key[sa_index], ECDH_OUTPUT_IN_TEMPKEY,0x0000,true);
  
  
  // Add the ATECC Encryption Scheme here and update the value of the encrypted_aes_key
  atecc.AES_ECB_encrypt(aes_key,0xFFFF,false);
  memcpy(&encrypted_key[0],&atecc.AES_buffer[0],16);
  Serial.println("Encrypted AES Session Key: ");
  print_bytes(encrypted_key, sizeof(encrypted_key) );

  send_session_key(encrypted_key, init_vector, gateway_sa);
  
  vehicle_rx_count = 0;
  ecu_rx_count = 0;

}

void loop() {
  // put your main code here, to run repeatedly:
  if (vehicle_can.read(vehicle_msg)){
    vehicle_rx_timer = 0;
    vehicle_rx_count++;
    ecu_can.write(vehicle_msg);
    AMBER_LED_state = !AMBER_LED_state;
    int num_bytes = parseJ1939(vehicle_msg);
    Serial.println(num_bytes);
    if (num_bytes > 0){
      int sa_index = get_sa_index(sa);
      if (num_bytes > 8){
        Serial.println("RX transport message:");
      }
      Serial.printf("PGN: %04X, SA: %02X, DA: %02X, DLC: %d, Data: ", j1939_pgn, j1939_sa, j1939_da, num_bytes);
      print_bytes(j1939_data, num_bytes);
      if (j1939_pgn == DATA_SECURITY_PGN){
        Serial.println("RX DATA_SECURITY_PGN");
        uint8_t msg_len = j1939_data[0];
        uint8_t msg_type = j1939_data[1];
        if (msg_type == DM18_SESSION_KEY && msg_len == 26){ 
          memcpy(&encrypted_key[0],&j1939_data[2],16);
          memcpy(&init_vector[0],&j1939_data[18],10);
          atecc.ECDH(device_public_key[sa_index], ECDH_OUTPUT_IN_TEMPKEY,0x0000);
          atecc.AES_ECB_decrypt(encrypted_key); // This loads the key into the AES_buffer
          setup_aes_key(sa_index, init_vector, atecc.AES_buffer);
        }
        else if (msg_type == DM18_CMAC_TYPE && msg_len == 18){
          compare_cmacs(sa_index);
        }
        else if (msg_type == DM18_PUBLIC_KEY_TYPE && msg_len == 64){
          Serial.println("Loaded Device Public Key");
          memcpy(&device_public_key[sa_index][0],&j1939_data[2],64);
          Serial.println("Sending Public Key.");
          send_public_key(sa);
        }
      }
    }
  }
  if ( ecu_can.read(ecu_msg) ) {
    ecu_rx_timer = 0;
    ecu_rx_count++;
    vehicle_can.write(ecu_msg);
  }
}
