
#define CMAC_SEND_TIME_MS  1000

#define CMAC_PAD_TIME_MICROS 1000 //Micros
#define MIN_CAN_TIME_SPACING 800 //Micros
#define SEND_DURING_PAUSE true
#define FIFO_ENABLED true  
#define NUM_TX_MAILBOXES 2
#define NUM_RX_MAILBOXES 32
#define SEQ_MSG false

#include "SecureJ1939.h"
#include <i2c_driver_wire.h>
#include <SparkFun_ATECCX08a_Arduino_Library.h>


#define RED_LED    3
#define GREEN_LED  2
#define YELLOW_LED 4
#define AMBER_LED  5

ATECCX08A atecc;


CAN_message_t vehicle_msg;
CAN_message_t ecu_msg;


boolean RED_LED_state;
boolean GREEN_LED_state;
boolean YELLOW_LED_state;
boolean AMBER_LED_state;

uint32_t vehicle_rx_count;
uint32_t ecu_rx_count;
uint8_t gateway_sa;

elapsedMillis vehicle_rx_timer;
elapsedMicros ecu_rx_timer;
elapsedMicros delay_timer;
elapsedMillis cmac_tx_timer;

void atecc_error_flash() {
  while (1) {
    //Setup Blinking pattern
    digitalWrite(AMBER_LED, LOW);
    digitalWrite(RED_LED, HIGH);
    delay(200);
    digitalWrite(YELLOW_LED, LOW);
    digitalWrite(GREEN_LED, HIGH);
    delay(200);
    digitalWrite(RED_LED, LOW);
    digitalWrite(AMBER_LED, HIGH);
    delay(200);
    digitalWrite(YELLOW_LED, HIGH);
    digitalWrite(GREEN_LED, LOW);
    delay(200);
  }
}

//int ecu_callback() {
//  ecu_can.events();
//  return 1;
//}
//int vehicle_callback() {
//  vehicle_can.events();
//  return 1;
//
//}


uint8_t message[16];

void setup(void) {
  gateway_sa = 37;

//  self_source_addr = 11+128; //Brake CAN Conditioner
//  num_ecu_source_addresses = 1;
//  ecu_source_addresses[0] = 11; //Brake Controller
//  //ecu_source_addresses[1] = 15; //Retarder
//  
//  num_veh_source_addresses = 12;
//  veh_source_addresses[0] = 249; // Diagnostic Tool
//  veh_source_addresses[1] = 37; //Gateway
//  veh_source_addresses[2] = 0; // Brake Controller
//  veh_source_addresses[3] = 128+0; //Brake CAN Conditioner
//  veh_source_addresses[4] = 3; // Transmission
//  veh_source_addresses[5] = 128+3; //Transmission CAN Conditioner
//  veh_source_addresses[6] = 33; // Body Controller
//  veh_source_addresses[7] = 128+33; //Retarder CAN Conditioner
//  veh_source_addresses[8] = 49; // Instrument Cluster
//  veh_source_addresses[9] = 128+49; // Body controller CAN Conditioner
//  veh_source_addresses[10] = 15; // Retarder
//  veh_source_addresses[11] = 128+15; // Retarder CAN Conditioner
//  
//  EEPROM.put(EEPROM_SELF_SOURCE_ADDR,self_source_addr);
//  EEPROM.put(EEPROM_NUM_ECU_SA_ADDR,num_ecu_source_addresses);
//  EEPROM.put(EEPROM_NUM_VEH_SA_ADDR,num_veh_source_addresses);
//  EEPROM.put(EEPROM_ECU_ADDR,ecu_source_addresses);
//  EEPROM.put(EEPROM_VEH_ADDR,veh_source_addresses);

  load_source_addresses();
  vehicle_can.begin();
  vehicle_can.setBaudRate(250000);
  vehicle_can.setMaxMB(NUM_TX_MAILBOXES + NUM_RX_MAILBOXES);
  if (FIFO_ENABLED) vehicle_can.enableFIFO();
  //vehicle_can.enableFIFOInterrupt();

  ecu_can.begin();
  ecu_can.setBaudRate(250000);
  ecu_can.setMaxMB(NUM_TX_MAILBOXES+NUM_RX_MAILBOXES);
  if (FIFO_ENABLED) ecu_can.enableFIFO();

  for (int i = 0; i<NUM_RX_MAILBOXES; i++){
    vehicle_can.setMB(i,RX,EXT);
    ecu_can.setMB(i,RX,EXT);
  }
  for (int i = NUM_RX_MAILBOXES; i<(NUM_TX_MAILBOXES + NUM_RX_MAILBOXES); i++){
    vehicle_can.setMB(i,TX,EXT);
    ecu_can.setMB(i,TX,EXT);
  }

  Serial5.begin(9600);
  pinMode(RED_LED, OUTPUT);
  pinMode(GREEN_LED, OUTPUT);
  pinMode(YELLOW_LED, OUTPUT);
  pinMode(AMBER_LED, OUTPUT);
  pinMode(LED_BUILTIN, OUTPUT);
  
  digitalWrite(LED_BUILTIN, HIGH);

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
  for (int i = 0; i < sizeof(atecc.serialNumber); i++) {
    if (2 * i >= sizeof(serial_string)) break; // Be sure not to overflow theserial strin buffer
    char hex_char[3];
    sprintf(hex_char, "%02X", atecc.serialNumber[i]);
    memcpy(&serial_string[2 * i], &hex_char, 2);
  }
  sprintf(model_string, "CANConditioner");

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
    if (atecc.generatePublicKey(0) == false) {
      Serial.println("Failure to generate this device's Public Key");
      atecc_error_flash();
    }
  }
  else
  {
    Serial.println("ATECC not Locked. Please provision correctly.");
    atecc_error_flash(); // stall out forever
  }
  
  digitalWrite(RED_LED, HIGH);
  
  // Produce Random Nonce for Session Key and Init. Vector
  atecc.updateRandom32Bytes();
  memcpy(&aes_key[0], &atecc.random32Bytes[0], sizeof(aes_key));
  memcpy(&init_vector[0], &atecc.random32Bytes[sizeof(aes_key)], sizeof(init_vector));

  Serial.println("Initialization Vector: ");
  print_bytes(init_vector, sizeof(init_vector));
  Serial.println("Plain AES Session Key: ");
  print_bytes(aes_key, sizeof(aes_key));

  memcpy(own_public_key, atecc.publicKey64Bytes, sizeof(own_public_key));
  Serial.println("Own Public Key: ");
  print_bytes(own_public_key, sizeof(own_public_key));

  digitalWrite(AMBER_LED, HIGH);
  

//  vehicle_can.mailboxStatus();
//  ecu_can.mailboxStatus();

  // Get Gateway Public Key
  bool received_public_key = false;
  elapsedMillis wait_timer;
  while (received_public_key == false) {
    vehicle_can.events(); //must process events
    if (wait_timer >= 2000) {
      wait_timer = 0;
      Serial.println("Sending Public Key");
      send_public_key(gateway_sa);
    }
    if (vehicle_can.read(vehicle_msg)) {
      int num_bytes = parseJ1939(vehicle_msg);
      if (num_bytes > 8){
        Serial.println("RX transport message:");
        Serial.printf("PGN: %04X, SA: %02X, DA: %02X, DLC: %d, Data: ", j1939_pgn, j1939_sa, j1939_da, num_bytes);
        print_bytes(j1939_data, num_bytes);
        if (j1939_pgn == DM18_PGN) {
          Serial.println("Data Security Message Found.");
          uint8_t msg_len = j1939_data[0];
          uint8_t msg_type = j1939_data[1];
          if (msg_type == DM18_PUBLIC_KEY_TYPE && msg_len == 64 ) {
            Serial.println("Setting device_public_key memory.");
            for (uint8_t i = 0; i < num_ecu_source_addresses; i++){
              memcpy(&device_public_key[i][0], &j1939_data[2], msg_len);
              atecc.ECDH(device_public_key[i], ECDH_OUTPUT_IN_TEMPKEY, 0x0000);
              atecc.AES_ECB_encrypt(aes_key); // This loads the key into the AES_buffer
              memcpy(&encrypted_key[0], &atecc.AES_buffer[0], 16);
              Serial.println("Encrypted AES Session Key: ");
              print_bytes(encrypted_key, sizeof(encrypted_key) );
              setup_aes_key(i, init_vector, aes_key); 
              send_session_key(encrypted_key, init_vector, gateway_sa, (ecu_source_addresses[i] & 0x7f)+0x80);
            }
            
            received_public_key = true;
            break;
          }
        }
      }
    }
  }
  digitalWrite(YELLOW_LED, HIGH);
  
  delay(5);

  //for (uint8_t i = 0; i < num_ecu_source_addresses; i++){
     
    wait_timer = 0;
    bool matching = false;
    while (matching == false) {
      vehicle_can.events();
      if (wait_timer >= 2000) {
        wait_timer = 0;
        for (uint8_t i = 0; i < num_ecu_source_addresses; i++){
          send_session_key(encrypted_key, init_vector, gateway_sa, (ecu_source_addresses[i] & 0x7f)+0x80);
        }
      }
      if (vehicle_can.read(vehicle_msg)) {
        //ecu_can.write(vehicle_msg);
        int num_bytes = parseJ1939(vehicle_msg);
        int veh_cmac_index = get_cmac_index(j1939_sa);
        
        //if (j1939_sa == ((ecu_source_addresses[i]&0x7F) + 0x80)){
          if (j1939_pgn == DM18_PGN ) {
            Serial.println("Data Security Message Found.");
            Serial.printf("PGN: %04X, SA: %02X, DA: %02X, DLC: %d, Data: ", j1939_pgn, j1939_sa, j1939_da, num_bytes);
            print_bytes(j1939_data, num_bytes);
            uint8_t msg_len = j1939_data[0];
            uint8_t msg_type = j1939_data[1];
            if (msg_type == DM18_CONFIRMATION_TYPE) {
              memcpy(&message[0], &j1939_data[2], sizeof(message));
              print_bytes(message,sizeof(message));
              atecc.ECDH(device_public_key[veh_cmac_index], ECDH_OUTPUT_IN_TEMPKEY, 0x0000);
              if (atecc.AES_ECB_decrypt(message,0xFFFF, false)){
                Serial.println("Confirming Key Exchange. The following should match:");
                print_bytes(atecc.AES_buffer, 10);
                print_bytes(init_vector, 10);
                matching = !memcmp(atecc.AES_buffer, init_vector, 10);
                if (matching) {
                  memcpy(&cmac_ready[0],&cmac_setup[0],sizeof(cmac_setup));
                  break;
                }
                else {
                  Serial.println("Keys did not match.");
                  delay(100);
                  digitalWrite(RED_LED, HIGH);
                  digitalWrite(YELLOW_LED, HIGH);
                  delay(100);
                  digitalWrite(RED_LED, LOW);
                  digitalWrite(YELLOW_LED, LOW);
                }  
              }
              else
              {
                Serial.println("Failed to execute decrypt");
              }
            }
         // }
        }
      } // end vehicle read message
    }
  //}
  digitalWrite(GREEN_LED, HIGH);
  digitalWrite(LED_BUILTIN, LOW);
  Serial.println("Starting Loop.");
  //delay(10);
  
  
}

void loop() {
  // put your main code here, to run repeatedly:
  vehicle_can.events();
  ecu_can.events();
  
  if (vehicle_can.read(vehicle_msg)) {
    vehicle_rx_timer = 0;
    vehicle_rx_count++;
    ecu_can.write(vehicle_msg);
    AMBER_LED_state = !AMBER_LED_state;
    int num_bytes = parseJ1939(vehicle_msg);
//    if (num_bytes > 0) {
//      if (num_bytes > 8) {
//        Serial.println("RX transport message:");
//        Serial.printf("PGN: %04X, SA: %02X, DA: %02X, DLC: %d, Data: ", j1939_pgn, j1939_sa, j1939_da, num_bytes);
//        print_bytes(j1939_data, num_bytes);
//      }
      if (j1939_pgn == DATA_SECURITY_PGN) {
        //Serial.println("RX DATA_SECURITY_PGN");
        uint8_t msg_len = j1939_data[0];
        uint8_t msg_type = j1939_data[1];
        if (msg_type == DM18_RESET_TYPE && j1939_sa == gateway_sa) {
          setup();
        }
      }
//    }
  }
  if ( ecu_can.read(ecu_msg) && ecu_rx_timer >= MIN_CAN_TIME_SPACING) {
    ecu_rx_timer = 0;
    ecu_rx_count++;
    YELLOW_LED_state = !YELLOW_LED_state;
    uint8_t ecu_sa = ecu_msg.id & 0xFF;
    int ecu_index = -1;
    for (int i = 0; i < num_ecu_source_addresses; i++){
      if (ecu_source_addresses[i] == ecu_sa){
        ecu_index = i;
      }
    }
    if (ecu_index < 0){
      // Send DM message for bad SA
      Serial.println("Found Bad Source Address.");
    }
    else {
      if (cmac_ready[ecu_index] ){
        if (SEQ_MSG) ecu_msg.seq = 1;
        vehicle_can.write(ecu_msg);
        vehicle_can.events();
        update_cmac(ecu_index,ecu_msg);
        if (cmac_tx_timer >= CMAC_SEND_TIME_MS) {
          cmac_tx_timer = 0;
          delayMicroseconds(CMAC_PAD_TIME_MICROS);
          send_cmac(ecu_sa+0x80, GATEWAY_SOURCE_ADDR, ecu_index);
          if (SEND_DURING_PAUSE) vehicle_can.events();
          delayMicroseconds(CMAC_PAD_TIME_MICROS);
          GREEN_LED_state = !GREEN_LED_state;
        }  
      }
    }
  }
      
  digitalWrite(RED_LED, RED_LED_state);
  digitalWrite(GREEN_LED, GREEN_LED_state);
  digitalWrite(YELLOW_LED, YELLOW_LED_state);
  digitalWrite(AMBER_LED, AMBER_LED_state);
}
