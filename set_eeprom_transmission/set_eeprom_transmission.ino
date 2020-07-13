#include <EEPROM.h>
#include "SecureJ1939_defs.h"

#define RED_LED    3
#define GREEN_LED  2
#define YELLOW_LED 4
#define AMBER_LED  5

void setup() {
  pinMode(RED_LED, OUTPUT);
  pinMode(GREEN_LED, OUTPUT);
  pinMode(YELLOW_LED, OUTPUT);
  pinMode(AMBER_LED, OUTPUT);
  pinMode(LED_BUILTIN, OUTPUT);
   
  //Crypographic Gateway EEPROM
   self_source_addr = 11 + 0x80; //Brake Controller CAN Conditioner
  
  num_ecu_source_addresses = 1;
  ecu_source_addresses[0] = 3; //Transmission Controller

  num_veh_source_addresses = 18;
  veh_source_addresses[0] = 0; // Engine
  veh_source_addresses[1] = 128+0; //Engine CAN Conditioner
  veh_source_addresses[2] = 11; // Brake
  veh_source_addresses[3] = 128+11; //Brake CAN Conditioner
  veh_source_addresses[4] = 15; //retarder
  veh_source_addresses[5] = 128+15; //Retarder CAN Conditioner
  veh_source_addresses[6] = 33; // Body controller
  veh_source_addresses[7] = 128+33; // Body controller CAN Conditioner
  veh_source_addresses[8] = 49; // Instrument Cluster
  veh_source_addresses[9] = 128+49; // Instrument Cluster CAN Conditioner
  veh_source_addresses[10] = 249; // Diagnostic Tool #1
  veh_source_addresses[11] = 250; // Diagnostic Tool #2
  veh_source_addresses[12] = 5; // 
  veh_source_addresses[13] = 128+5; // 
  veh_source_addresses[14]  = 37; //Secure Gateway
  veh_source_addresses[15] = 41; // Instrument Cluster
  veh_source_addresses[16] = 128+41; // Instrument Cluster CAN Conditioner
  veh_source_addresses[17] = 254; // Instrument Cluster CAN Conditioner
  
  
  EEPROM.put(EEPROM_SELF_SOURCE_ADDR,self_source_addr);
  EEPROM.put(EEPROM_NUM_ECU_SA_ADDR,num_ecu_source_addresses);
  EEPROM.put(EEPROM_NUM_VEH_SA_ADDR,num_veh_source_addresses);
  EEPROM.put(EEPROM_ECU_ADDR,ecu_source_addresses);
  EEPROM.put(EEPROM_VEH_ADDR,veh_source_addresses);
}

void loop() {
  //Setup Blinking pattern
  digitalWrite(AMBER_LED, LOW);
  digitalWrite(RED_LED, HIGH);
  digitalWrite(YELLOW_LED, LOW);
  digitalWrite(GREEN_LED, HIGH);
  delay(200);
  digitalWrite(RED_LED, LOW);
  digitalWrite(AMBER_LED, HIGH);
  digitalWrite(YELLOW_LED, HIGH);
  digitalWrite(GREEN_LED, LOW);
  delay(200);
}
