#include <EEPROM.h>
#include "SecureJ1939.h"
#include <i2c_driver_wire.h>
#include <SparkFun_ATECCX08a_Arduino_Library.h>

#define CMAC_SEND_TIME_MS  1000
#define CMAC_PAD_TIME_MICROS 500 //Micros
#define MIN_CAN_TIME_SPACING 400 //Micros
#define FIFO_ENABLED true  
#define SEQ_MSG true
#define NUM_TX_MAILBOXES         2
#define NUM_RX_MAILBOXES         NUM_SOURCE_ADDRESSES


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

elapsedMicros vehicle_tx_timer;
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

uint8_t message[16];

void setup(void) {
  pinMode(RED_LED, OUTPUT);
  pinMode(GREEN_LED, OUTPUT);
  pinMode(YELLOW_LED, OUTPUT);
  pinMode(AMBER_LED, OUTPUT);
  pinMode(LED_BUILTIN, OUTPUT);
  
  load_source_addresses();
  
 
  
  vehicle_can.begin();
  vehicle_can.setBaudRate(250000);
  vehicle_can.setMaxMB(NUM_TX_MAILBOXES + NUM_RX_MAILBOXES);
 
  ecu_can.begin();
  ecu_can.setBaudRate(250000);
  ecu_can.setMaxMB(NUM_TX_MAILBOXES+NUM_RX_MAILBOXES);
  
  for (int i = 0; i<NUM_RX_MAILBOXES; i++){
    vehicle_can.setMB(i,RX,EXT);
    ecu_can.setMB(i,RX,EXT);
  }
  for (int i = NUM_RX_MAILBOXES; i<(NUM_TX_MAILBOXES + NUM_RX_MAILBOXES); i++){
    vehicle_can.setMB(i,TX,EXT);
    ecu_can.setMB(i,TX,EXT);
  }

  if (FIFO_ENABLED) vehicle_can.enableFIFO();
  if (FIFO_ENABLED) ecu_can.enableFIFO();

  Serial5.begin(9600);
  
  
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
      for (uint8_t i = 0; i < num_ecu_source_addresses; i++){
        self_source_addr = get_self_source_addr(i);
        Serial.printf("Sending Public Key from 0x%02X to 0x%02X\n",self_source_addr,gateway_sa);
        send_public_key(gateway_sa);
      }
      
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
          if (msg_type == DM18_RESET_TYPE && j1939_sa == gateway_sa) {
              setup();
          }
          else if (msg_type == DM18_PUBLIC_KEY_TYPE && msg_len == 64 && j1939_da == self_source_addr) {
            Serial.println("Setting device_public_key memory.");
            memcpy(&device_public_key[0][0], &j1939_data[2], msg_len);
            print_bytes(device_public_key[0],sizeof(device_public_key[0]));
            atecc.ECDH(device_public_key[0], ECDH_OUTPUT_IN_TEMPKEY, 0x0000);
            atecc.AES_ECB_encrypt(aes_key); // This loads the key into the AES_buffer
            memcpy(&encrypted_key[0], &atecc.AES_buffer[0], 16);
            Serial.println("Encrypted AES Session Key: ");
            print_bytes(encrypted_key, sizeof(encrypted_key) );
            for (uint8_t i = 0; i < num_ecu_source_addresses; i++){
              setup_aes_key(i, init_vector, aes_key); 
              Serial.printf("Sending Encrypted Session Key from %02X to %02X\n",get_self_source_addr(i),gateway_sa);
              send_session_key(encrypted_key, init_vector, gateway_sa, get_self_source_addr(i));
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
          self_source_addr = get_self_source_addr(i);
          Serial.printf("Sending Encrypted Session Key from %02X to %02X\n",self_source_addr,gateway_sa);
          send_session_key(encrypted_key, init_vector, gateway_sa, self_source_addr);
        }
      }
      if (vehicle_can.read(vehicle_msg)) {
        //ecu_can.write(vehicle_msg);
        int num_bytes = parseJ1939(vehicle_msg);
//        if (j1939_da < 0xFF){
//          Serial.printf("PGN: %04X, SA: %02X, DA: %02X, DLC: %d, Data: ", j1939_pgn, j1939_sa, j1939_da, num_bytes);
//          print_bytes(j1939_data, num_bytes);
//        }
            
        int veh_cmac_index = get_veh_index(j1939_sa);
        if (j1939_pgn == DM18_PGN && num_bytes > 0) {
            Serial.println("Another Data Security Message Found.");
            Serial.printf("PGN: %04X, SA: %02X, DA: %02X, DLC: %d, Data: ", j1939_pgn, j1939_sa, j1939_da, num_bytes);
            print_bytes(j1939_data, num_bytes);
            uint8_t msg_len = j1939_data[0];
            uint8_t msg_type = j1939_data[1];
            if (msg_type == DM18_RESET_TYPE && j1939_sa == gateway_sa && j1939_da == self_source_addr) {
              setup();
            }
            else if (msg_type == DM18_CONFIRMATION_TYPE) {
              memcpy(&message[0], &j1939_data[2], sizeof(message));
              print_bytes(message,sizeof(message));
              //atecc.ECDH(device_public_key[0], ECDH_OUTPUT_IN_TEMPKEY, 0x0000);
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
                  for (int i = 0; i<4;i++){
                    delay(100);
                    digitalWrite(RED_LED, HIGH);
                    digitalWrite(YELLOW_LED, HIGH);
                    delay(100);
                    digitalWrite(RED_LED, LOW);
                    digitalWrite(YELLOW_LED, LOW);
                  }
                  setup();
            }  
          }
          else {
            Serial.println("Failed to execute decrypt");
          }
        }
      }
    } // end vehicle read message
  }
  digitalWrite(LED_BUILTIN, LOW);
  GREEN_LED_state = HIGH;
  RED_LED_state = HIGH;
  Serial.println("Starting Loop.");

  for (uint8_t i = 0; i < num_ecu_source_addresses; i++){
    cmac_receipt_timer[i] = 0;
  }   
  while ((vehicle_can.events() & 0xFFFFFF) > 0);
  while ((ecu_can.events() & 0xFFFFFF) > 0);
}

void loop() {
  // put your main code here, to run repeatedly:
  // Implement the "leaky bucket" concept where there are guaranteed gaps between messages.
  if (vehicle_tx_timer >= MIN_CAN_TIME_SPACING){
      vehicle_tx_timer = 0;
      vehicle_can.events();
  }     
  ecu_can.events();
  
  if (vehicle_can.read(vehicle_msg)) {
    vehicle_rx_timer = 0;
    vehicle_rx_count++;
    int num_bytes = parseJ1939(vehicle_msg);
    bool message_ok = true;
    for (int i = 0; i < num_ecu_source_addresses; i++){
      //Serial.printf("Check SAs: %02X == %02X\n",j1939_sa,ecu_source_addresses[i]);
      if (j1939_sa == ecu_source_addresses[i]){
        message_ok = false;
        //SPN 10841: Impostor PG Source Address
        //FMI 19: Received Network Data In Error
        update_DM1_message(IMPOSTOR_PG_SOURCE_ADDRESS, RECEIVED_NETWORK_DATA_IN_ERROR);
        update_pg_alert_msg(vehicle_msg);
      }
    }
    if (j1939_pgn == DATA_SECURITY_PGN) {
      uint8_t msg_len = j1939_data[0];
      uint8_t msg_type = j1939_data[1];
      if (msg_type == DM18_RESET_TYPE && j1939_sa == gateway_sa) {
        // TODO: Use a cryptographic code to reset so only the gateway can do it.
        setup();
      }
      else if (msg_type == DM18_CMAC_TYPE){
        for (int i = 0; i < num_ecu_source_addresses; i++){
          if (j1939_da == (ecu_source_addresses[i] + 0x80) || j1939_da == ecu_source_addresses[i]){
            Serial.printf("Found CMAC Receipt for %02X %d\n",j1939_da, cmac_counter[i]);
            cmac_receipt_timer[i] = 0;
          }
        }
      }
    }
    else if (message_ok){
      ecu_can.write(vehicle_msg);
      AMBER_LED_state = !AMBER_LED_state;  
    }
  }

  if ( ecu_can.read(ecu_msg)) {
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
      update_pg_alert_msg(ecu_msg);
      update_DM1_message(IMPOSTOR_PG_SOURCE_ADDRESS, BAD_INTELLIGENT_DEVICE);      
    }
    else {
      // Make sure all messages are transmitted.
      while ((vehicle_can.events() & 0xFFFFFF) > 0);
      if (cmac_ready[ecu_index] ){
        if (SEQ_MSG) ecu_msg.seq = 1;
        vehicle_can.write(ecu_msg);
        update_cmac(ecu_index,ecu_msg);
        
        if (vehicle_tx_timer >= MIN_CAN_TIME_SPACING){
          vehicle_tx_timer = 0;
          vehicle_can.events();
        } 
        
      }
    }
  }
  
  if (cmac_tx_timer >= CMAC_SEND_TIME_MS) {
    cmac_tx_timer = 0;
    for (uint8_t i = 0; i < num_ecu_source_addresses; i++){
      self_source_addr = get_self_source_addr(i);
      
      // Make sure all messages are sent out before sending the CMAC
      while ((vehicle_can.events() & 0xFFFFFF) > 0);
      delayMicroseconds(CMAC_PAD_TIME_MICROS);
      send_cmac(self_source_addr, GATEWAY_SOURCE_ADDR, i);
      
      // Make sure the CMAC is sent out before any other messages are sent to the queue
      while ((vehicle_can.events() & 0xFFFFFF) > 0);
      delayMicroseconds(CMAC_PAD_TIME_MICROS);
    }
    GREEN_LED_state = !GREEN_LED_state;
  }   

  //check timeouts:
  if (dm1_message_timer >= DM1_MESSAGE_TIMEOUT){
    dm1_message_timer = 0;
    vehicle_can.write(dm1_msg);
    // Not CMACing out of band comms yet. update_cmac(0,dm1_msg); // use the first index.
  }
  if (impostor_pg_message_timer >= IMPOSTOR_PG_MESSAGE_TIMEOUT){
    impostor_pg_message_timer = 0;
    impostor_found = false;
    vehicle_can.write(impostor_msg);
    update_cmac(0,impostor_msg); // use the first index
  }
  
  for (uint8_t i = 0; i < num_ecu_source_addresses; i++){
    if (cmac_receipt_timer[i] > (3*CMAC_SEND_TIME_MS)){
      cmac_receipt_timer[i] = 0;
      self_source_addr = get_self_source_addr(i);
      update_DM1_message(PASSWORD_VALID_INDICATOR, ABNORMAL_UPDATE_RATE);
    }
  }
  //reset the LEDs if there is no vehicle CAN traffic
  if (vehicle_rx_timer > MESSAGE_TIMEOUT) AMBER_LED_state = LOW;
  if (ecu_rx_timer > MESSAGE_TIMEOUT) YELLOW_LED_state = LOW;
  
 
  digitalWrite(RED_LED, RED_LED_state);
  digitalWrite(GREEN_LED, GREEN_LED_state);
  digitalWrite(YELLOW_LED, YELLOW_LED_state);
  digitalWrite(AMBER_LED, AMBER_LED_state);
}
