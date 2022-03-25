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
   
  //Engine CAN Conditioner
  num_ecu_source_addresses = 2;
  ecu_source_addresses[0] = 0; //Engine Controller
  ecu_source_addresses[1] = 15; //Retarder
  //ecu_source_addresses[2] = 41; //Inst
          
  num_veh_source_addresses = 17;
  veh_source_addresses[0] = 249; // Diagnostic Tool
  veh_source_addresses[1] = 37; //Gateway
  veh_source_addresses[2] = 11; // Brake Controller
  veh_source_addresses[3] = 128+11; //Brake CAN Conditioner
  veh_source_addresses[4] = 3; // Transmission
  veh_source_addresses[5] = 128+3; //Transmission CAN Conditioner
  veh_source_addresses[6] = 33; // Body Controller
  veh_source_addresses[7] = 128+33; //Retarder CAN Conditioner
  veh_source_addresses[8] = 49; // Instrument Cluster
  veh_source_addresses[9] = 128+49; // Body controller CAN Conditioner
  veh_source_addresses[10] = 15; // Retarder
  veh_source_addresses[11] = 128+15; // Retarder CAN Conditioner
  veh_source_addresses[12] = 5; // Shift Console controller
  veh_source_addresses[13] = 128+5; // Shift Console controller CAN Conditioner
  veh_source_addresses[14] = 41; // Inst controller
  veh_source_addresses[15] = 128+41; // Inst controller CAN Conditioner
  veh_source_addresses[16] = 254; // Null Address
   
  EEPROM.put(EEPROM_SELF_SOURCE_ADDR,ecu_source_addresses[0]+0x80);
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
