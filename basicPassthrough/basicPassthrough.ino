/*
 * Sketch for the CAN Conditioner/Secure Gateway 
 * This sketch simply passes CAN data from one channel to another
 * If an LCD display is connected, the display updates with the
 * message counts. 
 */
#include <FlexCAN_T4.h>

#define CAN_BAUD_RATE 250000

#define RED_LED    3
#define GREEN_LED  2
#define YELLOW_LED 4
#define AMBER_LED  5 

#define DISPLAY_TIMEOUT 750
#define MESSAGE_TIMEOUT 150 //milliseconds

FlexCAN_T4<CAN1, RX_SIZE_256, TX_SIZE_16> vehicle_can;
FlexCAN_T4<CAN2, RX_SIZE_256, TX_SIZE_16> ecu_can;

CAN_message_t vehicle_msg;
CAN_message_t ecu_msg;

boolean first_frame = false;
boolean consecutive_frame = false;
uint32_t idx;
uint32_t sequence;
uint8_t last_message_seq = 0xFF;
uint16_t blocks;
boolean new_block = false;
uint16_t segment;
uint8_t send_counter;
uint8_t data[8];

uint8_t sent_message_buffer[4096];

uint32_t TXcount;
uint32_t RXcount;
boolean RED_LED_state;
boolean GREEN_LED_state;
boolean YELLOW_LED_state;
boolean AMBER_LED_state;

uint32_t vehicle_rx_count;
uint32_t ecu_rx_count;
  
elapsedMillis vehicle_rx_timer;
elapsedMillis ecu_rx_timer;
elapsedMillis display_update_timer;

char display_buffer[17] = {};

byte counter = 0;
byte contrast = 2; //Lower is more contrast. 0 to 5 works for most displays.

#define LCD_CONTRAST_COMMAND 24
#define LCD_SETTING_COMMAND  124
#define LCD_CLEAR_COMMAND    45
#define LCD_COMMAND          254
#define LCD_FIRST_LINE       128
#define LCD_SECOND_LINE      192

void setup(void) {
  Serial5.begin(9600);
  pinMode(RED_LED,OUTPUT);
  pinMode(GREEN_LED,OUTPUT);
  pinMode(YELLOW_LED,OUTPUT);
  pinMode(AMBER_LED,OUTPUT);
  pinMode(LED_BUILTIN,OUTPUT);
  
  RED_LED_state = true;
  
  vehicle_can.begin();
  vehicle_can.setBaudRate(CAN_BAUD_RATE);
  ecu_can.begin();
  ecu_can.setBaudRate(CAN_BAUD_RATE);
  
  vehicle_rx_timer = 0;
  ecu_rx_timer = 0;
  
  vehicle_rx_count = 0;
  ecu_rx_count = 0;
  
  Serial5.write('|'); //Put LCD into setting mode
  Serial5.write(LCD_CONTRAST_COMMAND); //Send contrast command
  Serial5.write(contrast);
  
}

void loop() {
  if (vehicle_can.read(vehicle_msg)){
    vehicle_rx_timer = 0;
    vehicle_rx_count++;
    AMBER_LED_state = !AMBER_LED_state;
    ecu_can.write(vehicle_msg);
  }
  
  if (ecu_can.read(ecu_msg)) {
    ecu_rx_timer = 0;
    ecu_rx_count++;
    YELLOW_LED_state = !YELLOW_LED_state;
    vehicle_can.write(ecu_msg);
  }

  //reset the LEDs if there is no vehicle CAN traffic
  if (vehicle_rx_timer > MESSAGE_TIMEOUT) AMBER_LED_state = LOW;
  if (ecu_rx_timer > MESSAGE_TIMEOUT) YELLOW_LED_state = LOW;

  if (display_update_timer > DISPLAY_TIMEOUT){
    display_update_timer = 0;
    Serial5.write(LCD_COMMAND);
    Serial5.write(LCD_FIRST_LINE);
    memset(display_buffer,0,sizeof(display_buffer));
    snprintf(display_buffer,sizeof(display_buffer),"nECU:%11d", ecu_rx_count);
    Serial5.print(display_buffer);
    
    Serial5.write(LCD_COMMAND);
    Serial5.write(LCD_SECOND_LINE);
    memset(display_buffer,0,sizeof(display_buffer));
    snprintf(display_buffer,sizeof(display_buffer),"1939:%11d", vehicle_rx_count);
    Serial5.write(display_buffer);
  }

  digitalWrite(RED_LED,RED_LED_state);
  digitalWrite(GREEN_LED,GREEN_LED_state);
  digitalWrite(YELLOW_LED,YELLOW_LED_state);
  digitalWrite(AMBER_LED,AMBER_LED_state);
  
  
}

      
