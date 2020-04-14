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
uint8_t message_for_cmac[16];
    
CAN_message_t vehicle_msg;
CAN_message_t ecu_msg;


boolean RED_LED_state;
boolean GREEN_LED_state;
boolean YELLOW_LED_state;
boolean AMBER_LED_state;

uint32_t vehicle_rx_count;
uint32_t ecu_rx_count;
uint8_t sa_index;
uint8_t gateway_sa;

elapsedMillis vehicle_rx_timer;
elapsedMillis ecu_rx_timer;
elapsedMillis cmac_timer;

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
  else {
    Serial.println("NOT Locked");
    atecc_error_flash();
  }

  Serial.print("Data/OTP Zone: \t");
  if (atecc.dataOTPLockStatus) Serial.println("Locked");
  else {
    Serial.println("NOT Locked");
    atecc_error_flash();
  }

  // Data Slot 0 is where we store the private key
  Serial.print("Data Slot 0: \t");
  if (atecc.slot0LockStatus) Serial.println("Locked");
  else {
    Serial.println("NOT Locked");
    atecc_error_flash();
  }
  // if everything is locked up, then configuration is complete, so let's print the public key
  if (atecc.configLockStatus && 
      atecc.dataOTPLockStatus && 
      atecc.slot0LockStatus) {
    if(atecc.generatePublicKey(0) == false){
      Serial.println("Failure to generate this device's Public Key");
      atecc_error_flash();
    }
  }
  else
  { 
    Serial.println("ATECC not Locked. Please provision correctly.");
    atecc_error_flash(); // stall out forever
  }

  // Produce Random Nonce for Session Key and Init. Vector
  atecc.updateRandom32Bytes();
  memcpy(&aes_key[0],&atecc.random32Bytes[0],sizeof(aes_key));
  memcpy(&init_vector[0],&atecc.random32Bytes[sizeof(aes_key)],sizeof(init_vector));
  
  Serial.println("Plain AES Session Key: ");
  print_bytes(aes_key, sizeof(aes_key));

  memcpy(own_public_key,atecc.publicKey64Bytes,sizeof(own_public_key));
  Serial.println("Own Public Key: ");
  print_bytes(own_public_key, sizeof(own_public_key));

  // Get Gateway Public Key
  
  gateway_sa = 37;
  sa_index = get_sa_index(gateway_sa);
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
  delay(5);
  wait_timer = 0;
  bool matching = false;
  while (matching == false){
    if (wait_timer >= 2000){
      wait_timer = 0;
      send_session_key(encrypted_key, init_vector, gateway_sa);
    }
    if (vehicle_can.read(vehicle_msg)){
      //ecu_can.write(vehicle_msg);
      int num_bytes = parseJ1939(vehicle_msg);
      if (j1939_pgn == DM18_PGN){
        Serial.println("Data Security Message Found.");
        Serial.printf("PGN: %04X, SA: %02X, DA: %02X, DLC: %d, Data: ", j1939_pgn, j1939_sa, j1939_da, num_bytes);
        print_bytes(j1939_data, num_bytes);
        uint8_t msg_len = j1939_data[0];
        uint8_t msg_type = j1939_data[1];
        if (msg_type == DM18_CONFIRMATION_TYPE){
          uint8_t message[16];
          memcpy(&message[0],&j1939_data[2],sizeof(message));
          atecc.AES_ECB_decrypt(message);
          Serial.println("Confirming Key Exchange. The following should match:");
          print_bytes(atecc.AES_buffer,10);
          print_bytes(init_vector,10);
          matching = !memcmp(atecc.AES_buffer,init_vector,10);
          if (matching) break;
        }
      }
    } // end vehicle read message
    if ( ecu_can.read(ecu_msg) ) {
      vehicle_can.write(ecu_msg);
    }
  }
}

void loop() {
  // put your main code here, to run repeatedly:
  if (vehicle_can.read(vehicle_msg)){
    vehicle_rx_timer = 0;
    vehicle_rx_count++;
    ecu_can.write(vehicle_msg);
    AMBER_LED_state = !AMBER_LED_state;
    int num_bytes = parseJ1939(vehicle_msg);
    if (num_bytes > 0){
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
    update_cmac(ecu_msg);
    vehicle_can.write(ecu_msg);
  }
  if (cmac_timer >= 2000){
    cmac_timer = 0;
    //Make a copy to produce an intermediate result
    memcpy(&cmac_copy[sa_index],&cmac[sa_index],sizeof(cmac[sa_index]));
    memcpy(&omac_copy[sa_index],&omac[sa_index],sizeof(omac[sa_index]));
    Serial.println("CMAC Copy Finalize:");
    cmac_copy[sa_index].finalize(omac_copy[sa_index]);
    print_bytes(omac_copy[sa_index],sizeof(omac_copy[sa_index]));
    vehicle_msg.id = 0x18D40000; //DM18 Message with normal priority
    vehicle_msg.id += gateway_sa << 8;
    vehicle_msg.id += SELF_SOURCE_ADDR;
    vehicle_msg.len = 8;
    vehicle_msg.buf[0] = 6; //Length
    vehicle_msg.buf[1] = DM18_CMAC_TYPE;
    memcpy(&vehicle_msg.buf[2],omac_copy[sa_index],6);
    vehicle_can.write(vehicle_msg);
    Serial.println("Sent 6 bytes of OMAC: ");
    print_bytes(vehicle_msg.buf,6);
    update_cmac(vehicle_msg); // update with messages generate
  }

  digitalWrite(RED_LED,RED_LED_state);
  digitalWrite(GREEN_LED,GREEN_LED_state);
  digitalWrite(YELLOW_LED,YELLOW_LED_state);
  digitalWrite(AMBER_LED,AMBER_LED_state);
}
void update_cmac(CAN_message_t msg){
  memset(message_for_cmac,0,sizeof(message_for_cmac));
  memcpy(&message_for_cmac[0],&msg.id,4);
  message_for_cmac[4] = msg.len;
  memcpy(&message_for_cmac[5],&msg.buf[0],msg.len);
  cmac[sa_index].update(omac[sa_index],message_for_cmac,sizeof(message_for_cmac));
}
