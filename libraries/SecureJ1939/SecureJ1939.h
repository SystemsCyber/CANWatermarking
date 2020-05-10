#include <FlexCAN_T4.h>
#include <AES.h>
#include <OMAC.h>
#include "SecureJ1939_defs.h"

FlexCAN_T4<CAN1, RX_SIZE_256, TX_SIZE_1024> vehicle_can;
FlexCAN_T4<CAN2, RX_SIZE_256, TX_SIZE_1024> ecu_can;

char serial_string[19];
char model_string[14];
uint32_t intrusion_count;
uint32_t success_count;

elapsedMillis dm1_message_timer;
elapsedMillis impostor_pg_message_timer;
elapsedMillis imposter_timer;

CAN_message_t impostor_msg;
CAN_message_t dm1_msg;
uint8_t imposter_alert_counter;
bool impostor_found = false;
uint8_t dm1_occurrance_count;

uint8_t own_public_key[64];
uint8_t source_addresses[NUM_SOURCE_ADDRESSES];
uint8_t encrypted_session_key[NUM_SOURCE_ADDRESSES][16];
uint8_t device_public_key[NUM_SOURCE_ADDRESSES][64];
bool device_public_key_received[NUM_SOURCE_ADDRESSES];
uint8_t cmac_data[NUM_SOURCE_ADDRESSES][CMAC_BLOCK_SIZE];
uint8_t cmac_keys[NUM_SOURCE_ADDRESSES][AES_BLOCK_SIZE];
uint8_t omac[NUM_SOURCE_ADDRESSES][AES_BLOCK_SIZE];
uint8_t omac_copy[NUM_SOURCE_ADDRESSES][AES_BLOCK_SIZE];
uint32_t cmac_counter[NUM_SOURCE_ADDRESSES];
uint32_t cmac_success_counter[NUM_SOURCE_ADDRESSES];
uint32_t cmac_error_counter[NUM_SOURCE_ADDRESSES];
OMAC cmac[NUM_SOURCE_ADDRESSES];
OMAC cmac_copy[NUM_SOURCE_ADDRESSES];
AES128 cmac_cipher[NUM_SOURCE_ADDRESSES];
bool cmac_setup[NUM_SOURCE_ADDRESSES];
bool cmac_ready[NUM_SOURCE_ADDRESSES];
elapsedMillis cmac_timer[NUM_SOURCE_ADDRESSES];
elapsedMillis cmac_receipt_timer[NUM_SOURCE_ADDRESSES];
uint8_t next_source_address_index = 0;
int current_sa = -1;

uint8_t encrypted_key[16];
uint8_t init_vector[16];
uint8_t aes_key[16];

uint8_t cmac_init_vector[NUM_SOURCE_ADDRESSES][16];
uint8_t cmac_aes_key[NUM_SOURCE_ADDRESSES][16];

uint8_t da_index;

bool key_confirmation_sent[256] = {};


const uint8_t gateway_sa = GATEWAY_SOURCE_ADDR;


void load_source_addresses(){
  EEPROM.get(EEPROM_SELF_SOURCE_ADDR,self_source_addr);
  EEPROM.get(EEPROM_NUM_ECU_SA_ADDR,num_ecu_source_addresses);
  EEPROM.get(EEPROM_NUM_VEH_SA_ADDR,num_veh_source_addresses);
  EEPROM.get(EEPROM_ECU_ADDR,ecu_source_addresses);
  EEPROM.get(EEPROM_VEH_ADDR,veh_source_addresses);

  Serial.printf("self_source_addr = %02X\n",self_source_addr);
  Serial.printf("num_ecu_source_addresses = %d\n",num_ecu_source_addresses);
  for (int i = 0;i<num_ecu_source_addresses;i++){
    Serial.printf("ecu_source_addresses[%d] = 0x%02X\n",i,ecu_source_addresses[i]);
  }
  Serial.printf("num_veh_source_addresses = %d\n",num_veh_source_addresses);
  for (int i = 0;i<num_veh_source_addresses;i++){
    Serial.printf("veh_source_addresses[%d] = 0x%02X\n",i,veh_source_addresses[i]);
  }
}

int get_ecu_index(uint8_t sa){
  for (int i = 0; i < num_ecu_source_addresses; i++){
    if (veh_source_addresses[i] == (sa & 0xFF)){
      return i;
    }
  }
  return -1;
}

int get_veh_index(uint8_t sa){
  for (int i = 0; i < num_veh_source_addresses; i++){
    if (veh_source_addresses[i] == (sa & 0xFF)){
      return i;
    }
  }
  return -1;
}

// // Use the index from the source address array to 
int get_sa_index(uint8_t sa){
  int sa_index = -1;
  for (uint16_t i = 0; i < NUM_SOURCE_ADDRESSES; i++){
    if (sa == source_addresses[i]){
      sa_index = i;
      break;
    }
  }
  
  if (sa_index < 0) {
    source_addresses[next_source_address_index] = sa;
    sa_index = next_source_address_index;
    next_source_address_index++;
    if (next_source_address_index >= NUM_SOURCE_ADDRESSES) {
      Serial.println("Source Address Space Exceeded");
      next_source_address_index = 0;
    }
  }
  //Serial.printf("Index for %02X is %d\n",sa,sa_index);
  return sa_index;
}

uint32_t pgn;
uint8_t sa;
uint8_t da;
uint8_t dlc;
uint8_t priority;


// A terribly inefficent way to setup transport layer buffers,
// But it's on a teensy, so who cares
uint8_t tp_messages[NUM_SOURCE_ADDRESSES][NUM_DESTINATION_ADDRESSES][J1939_MAX_LENGTH];
uint8_t j1939_data[J1939_MAX_LENGTH];  
uint32_t j1939_pgn;
uint8_t j1939_sa;
uint8_t j1939_da;

uint8_t message_for_cmac[16];

//Keep track of transport messages
uint8_t tp_message_state[NUM_SOURCE_ADDRESSES][NUM_DESTINATION_ADDRESSES][10];



uint8_t get_self_source_addr(uint8_t index){
  return (ecu_source_addresses[index] & 0x7f)+0x80;
}

void setup_aes_key(uint8_t cmac_index, uint8_t *init_vector, uint8_t *aes_key){
  //Serial.printf("Set Key for CMAC %0d\n",cmac_index);
  cmac_cipher[cmac_index].setKey(aes_key, sizeof(aes_key));
  cmac[cmac_index].setBlockCipher(&cmac_cipher[cmac_index]);
  
  Serial.println("Initializing CMAC");
  cmac[cmac_index].initFirst(omac[cmac_index]);
  memset(omac[cmac_index],0,sizeof(omac[cmac_index]));
  //cmac[cmac_index].update(omac[cmac_index],init_vector,sizeof(init_vector));
  Serial.printf("Setting cmac_setup[%d] to true.\n",cmac_index);
  cmac_setup[cmac_index] = true;
  cmac_timer[cmac_index] = 0;
  cmac_counter[cmac_index] = 0;
  cmac_error_counter[cmac_index] = 0;
  cmac_success_counter[cmac_index] = 0;

  imposter_alert_counter = 0;
  imposter_timer = 0;
  impostor_msg.id = 0x0C000000; //Priority 2
  impostor_msg.id = IMPOSTOR_PG_ALERT_PGN << 8;  
  impostor_msg.id += ecu_source_addresses[0];
  impostor_msg.len = 8;
  impostor_msg.flags.extended = 1;
  impostor_msg.buf[0] = 0;   // 10840: Impostor PG Event Detection Counter
  impostor_msg.buf[1] = 254; //10841: Impostor PG Source Address
  impostor_msg.buf[2] = 254; // 10842: Impostor PG Destination Address
  impostor_msg.buf[3] = 255; // 10843: Impostor PGN - LSB
  impostor_msg.buf[4] = 255; // 10843: Impostor PGN - 2nd Byte
  impostor_msg.buf[5] = 255; // 10843: Impostor PGN - MSB
  impostor_msg.buf[6] = 251; //10844: Time Since Last Imposter PG Detected
  impostor_msg.buf[7] = 255; //Not used
  impostor_msg.seq = 1;

  dm1_occurrance_count = 0;
  dm1_msg.id = 0x18FECA00; //Priority 6 DM1 Message
  dm1_msg.id += get_self_source_addr(0);
  dm1_msg.len = 8;
  dm1_msg.flags.extended = 1;
  dm1_msg.buf[0] = 0; // LAMP
  dm1_msg.buf[1] = 255; // FLASH
  dm1_msg.buf[2] = 0; // SPN
  dm1_msg.buf[3] = 0; // SPN
  dm1_msg.buf[4] = 0; // SPN and FMI
  dm1_msg.buf[5] = 0; // Conversion method and Occurrance Count
  dm1_msg.buf[6] = 255; //10844: Time Since Last Imposter PG Detected
  dm1_msg.buf[7] = 255; //Not used
  dm1_msg.seq = 1;

}


void print_bytes(byte bytes_to_print[], int array_size){
  for (uint16_t i = 0; i < array_size; i++)
  { 
    char hex_digit[3];
    sprintf(hex_digit,"%02X",bytes_to_print[i]);
    Serial.print(hex_digit);
  }
  Serial.println();
}

void send_frame(uint32_t pgn, uint8_t dest, uint8_t src, uint8_t *data, uint8_t dlc, uint8_t priority){
  CAN_message_t msg;
  msg.len = dlc & 0x0F;
  msg.id = priority << 26 ;
  //Serial.printf("PGN to send: %04X\n",pgn);
  msg.id += pgn << 8;
  if (pgn < 0xF000){
    msg.id += dest << 8;
  }
  msg.id += src;
  //Serial.printf("Sending ID %08X ",msg.id);
  //print_bytes(data,8);
  memcpy(&msg.buf[0], data, dlc);
  msg.flags.extended = 1;
  msg.seq = 1; // Puts the message in the queue to be sent.
  vehicle_can.write(msg);
  while ((vehicle_can.events() & 0xFFFFFF) > 0);// Serial.println(uint32_t(vehicle_can.events() & 0xFFFFFF)); 
}

void send_multi_frame(uint8_t dest, uint8_t src, uint8_t *data, uint8_t start_packet, uint8_t packets_to_send){  
  for (uint8_t i = start_packet; i < packets_to_send; i++){
    uint8_t data_to_send[8];
    data_to_send[0] = i+1;
    memcpy(&data_to_send[1],&data[i*7],7);
    send_frame(TP_DT_PGN, dest, src, data_to_send, sizeof(data_to_send), NORMAL_PRIORITY);
  }
}

void send_public_key_request(uint8_t da){
  uint8_t data_to_send[2];
  data_to_send[0] = 0; //Zero Length for a request
  data_to_send[1] = DM18_PUBLIC_KEY_TYPE;
  send_frame(DM18_PGN, da, get_self_source_addr(0), data_to_send, sizeof(data_to_send), NORMAL_PRIORITY);
}

void send_public_key(uint8_t da){
  uint8_t data_to_send[66];
  data_to_send[0] = 64; 
  data_to_send[1] = DM18_PUBLIC_KEY_TYPE;
  memcpy(&data_to_send[2], &own_public_key[0], sizeof(own_public_key));
  uint8_t packets_to_send = sizeof(data_to_send)/7 + bool(sizeof(data_to_send)%7);
  uint8_t setup_to_send[8];
  setup_to_send[0] = CM_BAM;
  setup_to_send[1] = sizeof(data_to_send) & 0xFF;
  setup_to_send[2] = (sizeof(data_to_send) & 0xFF00) >> 8;
  setup_to_send[3] = packets_to_send;
  setup_to_send[4] = 0xFF; //SAE specified
  setup_to_send[5] = (DM18_PGN & 0xFF);
  setup_to_send[6] = (DM18_PGN & 0xFF00) >> 8;
  setup_to_send[7] = (DM18_PGN & 0x030000) >> 16;
  //BAM
  send_frame(TP_CM_PGN, da, self_source_addr, setup_to_send, sizeof(setup_to_send), NORMAL_PRIORITY);
  uint8_t start_packet = 0;
  //Send to destination 
  send_multi_frame(da, self_source_addr, data_to_send, start_packet, packets_to_send);
}

void send_session_key_request(uint8_t da){
  uint8_t data_to_send[2];
  data_to_send[0] = 0; //Zero Length for a request
  data_to_send[1] = DM18_SESSION_KEY;
  send_frame(DM18_PGN, da, self_source_addr, data_to_send, sizeof(data_to_send), NORMAL_PRIORITY);
}

void send_session_key(uint8_t *encrypted_key, uint8_t *iv, uint8_t da, uint8_t s_addr){
  uint8_t data_to_send[28];
  data_to_send[0] = 26; 
  data_to_send[1] = DM18_SESSION_KEY;
  memcpy(&data_to_send[2], &encrypted_key[0], 16);
  memcpy(&data_to_send[18], &iv[0], 10);
  uint8_t packets_to_send = sizeof(data_to_send)/7 + bool(sizeof(data_to_send)%7);
  uint8_t setup_to_send[8];
  setup_to_send[0] = CM_BAM;
  setup_to_send[1] = sizeof(data_to_send) & 0xFF;
  setup_to_send[2] = (sizeof(data_to_send) & 0xFF00) >> 8;
  setup_to_send[3] = packets_to_send;
  setup_to_send[4] = 0xFF; //SAE specified
  setup_to_send[5] = (DM18_PGN & 0xFF);
  setup_to_send[6] = (DM18_PGN & 0xFF00) >> 8;
  setup_to_send[7] = (DM18_PGN & 0x030000) >> 16;
  //BAM
  send_frame(TP_CM_PGN, da, s_addr, setup_to_send, sizeof(setup_to_send), NORMAL_PRIORITY);
  uint8_t start_packet = 0;
  //Send to destination 
  send_multi_frame(da, s_addr, data_to_send, start_packet, packets_to_send);
}

void send_key_confirmation(uint8_t *encrypted_msg, uint8_t da){
  uint8_t data_to_send[18];
  data_to_send[0] = 16; 
  data_to_send[1] = DM18_CONFIRMATION_TYPE;
  memcpy(&data_to_send[2], &encrypted_msg[0], 16);
  uint8_t packets_to_send = sizeof(data_to_send)/7 + bool(sizeof(data_to_send)%7);
  uint8_t setup_to_send[8];
  setup_to_send[0] = CM_BAM;
  setup_to_send[1] = sizeof(data_to_send) & 0xFF;
  setup_to_send[2] = (sizeof(data_to_send) & 0xFF00) >> 8;
  setup_to_send[3] = packets_to_send;
  setup_to_send[4] = 0xFF; //SAE specified
  setup_to_send[5] = (DM18_PGN & 0xFF);
  setup_to_send[6] = (DM18_PGN & 0xFF00) >> 8;
  setup_to_send[7] = (DM18_PGN & 0x030000) >> 16;
  //BAM
  send_frame(TP_CM_PGN, da, self_source_addr, setup_to_send, sizeof(setup_to_send), NORMAL_PRIORITY);
  uint8_t start_packet = 0;
  //Send to destination 
  send_multi_frame(da, self_source_addr, data_to_send, start_packet, packets_to_send);
}

void send_clear_to_send(uint32_t j1939_pgn, uint8_t packets, uint8_t next, uint8_t da){
  uint8_t data_to_send[8];
  data_to_send[0] = CM_CLEAR_TO_SEND;
  data_to_send[1] = packets;
  data_to_send[2] = next;
  data_to_send[3] = 0xFF; //SAE specified
  data_to_send[4] = 0xFF; //SAE specified
  data_to_send[5] = (j1939_pgn & 0xFF);
  data_to_send[6] = (j1939_pgn & 0xFF00) >> 8;
  data_to_send[7] = (j1939_pgn & 0x030000) >> 16;
  send_frame(TP_CM_PGN, da, self_source_addr, data_to_send, sizeof(data_to_send), NORMAL_PRIORITY); 
}

void send_end_of_msg_ack(uint32_t j1939_pgn, uint8_t packets, uint16_t num_bytes, uint8_t da){
  uint8_t data_to_send[8];
  data_to_send[0] = CM_END_OF_MESSAGE_ACK;
  data_to_send[1] = num_bytes & 0xFF;
  data_to_send[2] = (num_bytes & 0xFF00) >> 8;
  data_to_send[3] = packets;
  data_to_send[4] = 0xFF; //SAE specified
  data_to_send[5] = (j1939_pgn & 0xFF);
  data_to_send[6] = (j1939_pgn & 0xFF00) >> 8;
  data_to_send[7] = (j1939_pgn & 0x030000) >> 16;
  send_frame(TP_CM_PGN, da, self_source_addr, data_to_send, sizeof(data_to_send), NORMAL_PRIORITY);
}

void send_component_id(uint8_t dest){
  char comp_id[4+sizeof(model_string)+1+sizeof(serial_string)];
  memset(comp_id,0xFF,sizeof(comp_id));
  strncpy(&comp_id[0],'CSU*',4);
  strncpy(&comp_id[4],model_string,sizeof(model_string));
  comp_id[4+sizeof(model_string)] = '*';
  strncpy(&comp_id[4+sizeof(model_string)+1],serial_string,sizeof(serial_string));
  comp_id[sizeof(comp_id) - 1] = '*';
  Serial.println(comp_id);
  int sa_index = get_sa_index(dest);
  uint8_t da_index;
  uint8_t packets_to_send = sizeof(comp_id)/7 + bool(sizeof(comp_id)%7);;
  uint8_t data_to_send[8];
  data_to_send[0] = CM_BAM;
  data_to_send[1] = sizeof(comp_id) & 0xFF;
  data_to_send[2] = (sizeof(comp_id) & 0xFF00) >> 8;
  data_to_send[3] = packets_to_send;
  data_to_send[4] = 0xFF; //SAE specified
  data_to_send[5] = (COMPONENT_ID_PGN & 0xFF);
  data_to_send[6] = (COMPONENT_ID_PGN & 0xFF00) >> 8;
  data_to_send[7] = (COMPONENT_ID_PGN & 0x030000) >> 16;
  //BAM
  send_frame(TP_CM_PGN, dest, self_source_addr, data_to_send, sizeof(data_to_send), NORMAL_PRIORITY);
  uint8_t start_packet = 0;
  uint8_t temp_buffer[sizeof(comp_id)];
  memcpy(&temp_buffer[0],comp_id,sizeof(comp_id));
  send_multi_frame(dest, self_source_addr, comp_id, start_packet, packets_to_send);
}

int parseJ1939(CAN_message_t msg){
  dlc = msg.len;
  sa = (msg.id & 0xFF);
  uint32_t pf = (msg.id & 0x3FF0000) >> 16;
  if (pf < 240){
    da = (msg.id & 0x00FF00) >> 8;
    pgn = pf << 8;
  }
  else{
    da = 0xff;  
    pgn = (msg.id & 0x3FFFF00) >> 8;
  }
  
  int sa_index = get_sa_index(sa);
  if (sa_index < 0) {
    Serial.printf("No Index for SA %02X\n",sa);
    return -1;
  }
    
  da_index = 254;

  if (da == 0xFF) {
    da_index = 0;
  }
  else {
    for (int i = 0; i < num_ecu_source_addresses; i++){
      //Serial.println(ecu_source_addresses[i],HEX);
      if (da == ecu_source_addresses[i]){
        da_index = 2*i + 1;
        break;
      }
      else if (da == (ecu_source_addresses[i] + 0x80)){
        da_index = 2*i + 2;
        break;
      }
    }
  }
  //Serial.printf("self: %02X, DA: %02X, index: %d\n",self_source_addr,da,da_index);
    
  memcpy(&j1939_data[0],&msg.buf[0],dlc);
  j1939_sa = sa;
  j1939_da = da;
  j1939_pgn = pgn;

  if (da_index == 254) return -1;
 
  if (pgn == REQUEST_PGN){
    //Serial.print("Found Request PGN: ");
    //print_bytes(msg.buf,msg.len);
    j1939_pgn = (msg.buf[2] << 16) + (msg.buf[1] << 8) + msg.buf[0];
    // Send a response if the PGN is supported
    //Serial.printf("%X == %X\n",j1939_pgn,COMPONENT_ID_PGN);
    if (j1939_pgn == COMPONENT_ID_PGN){
      send_component_id(GLOBAL_ADDR);
    }
  }
  else if (pgn == TP_DT_PGN){
    memcpy(&tp_messages[sa_index][da_index][7*(msg.buf[0]-1)],&msg.buf[1],7);
    tp_message_state[sa_index][da_index][PACKET_COUNTER_INDEX]++;
//    Serial.print("Transport Layer Packets Received: ");
//    print_bytes(msg.buf,8);
//    Serial.print(tp_message_state[sa_index][da_index][PACKET_COUNTER_INDEX]);
//    Serial.print(" == ");
//    Serial.println(tp_message_state[sa_index][da_index][TOTAL_COUNT_INDEX]);
  
    if (tp_message_state[sa_index][da_index][PACKET_COUNTER_INDEX] == 
        tp_message_state[sa_index][da_index][TOTAL_COUNT_INDEX]){
      // data transfer complete
      uint16_t num_bytes;
      memcpy(&num_bytes, &tp_message_state[sa_index][da_index][TOTAL_BYTE_INDEX], 2);
      uint8_t packets = tp_message_state[sa_index][da_index][1];
      memcpy(&j1939_pgn, &tp_message_state[sa_index][da_index][PGN_INDEX], 4);
      if (tp_message_state[sa_index][da_index][BAM_CTS_RTS_INDEX] == CTS_RTS_TYPE &&  da == self_source_addr){
        // Only respond to things sent to us.
        send_end_of_msg_ack(j1939_pgn,num_bytes,packets,sa);
      }
      memcpy(&j1939_data[0], &tp_messages[sa_index][da_index][0],num_bytes);
      j1939_sa = sa;
      j1939_da = da;
      tp_message_state[sa_index][da_index][PACKET_COUNTER_INDEX] = 0;
      tp_message_state[sa_index][da_index][TOTAL_COUNT_INDEX] = 255;
//      Serial.print("TPDATA: ");
//      print_bytes(j1939_data,num_bytes);
      return num_bytes;  
    }  
  }
  else if (pgn == TP_CM_PGN){
    //Serial.print("Transport Layer Control Received: ");
    //print_bytes(msg.buf,8);
    uint8_t control_byte = msg.buf[0];
    if (control_byte == CM_BAM){//Broadcast Announce Message
      tp_message_state[sa_index][da_index][BAM_CTS_RTS_INDEX] = BAM_TYPE;
      tp_message_state[sa_index][da_index][PACKET_COUNTER_INDEX] = 0;
      tp_message_state[sa_index][da_index][TOTAL_COUNT_INDEX] = msg.buf[3];
      uint16_t msg_size = msg.buf[1] + (uint16_t(msg.buf[2]) << 8);
      memcpy(&tp_message_state[sa_index][da_index][TOTAL_BYTE_INDEX], &msg_size, 2);
      j1939_pgn = (msg.buf[7] << 16) + (msg.buf[6] << 8) + msg.buf[5];
      memcpy(&tp_message_state[sa_index][da_index][PGN_INDEX], &j1939_pgn, 4);
      memset(&tp_messages[sa_index][da_index][0],0xFF,J1939_MAX_LENGTH);
    }
    else if (control_byte == CM_REQUEST_TO_SEND){ //Request to Send
      tp_message_state[sa_index][da_index][BAM_CTS_RTS_INDEX] = CTS_RTS_TYPE;
      uint8_t next = 0;
      tp_message_state[sa_index][da_index][PACKET_COUNTER_INDEX] = next;
      uint8_t total_packets = msg.buf[3];
      tp_message_state[sa_index][da_index][TOTAL_COUNT_INDEX] = total_packets;
      uint8_t response_packets = msg.buf[4];
      tp_message_state[sa_index][da_index][COUNT_TO_SEND_INDEX] = response_packets;
      
      uint16_t msg_size = msg.buf[1] + (uint16_t(msg.buf[2]) << 8);
      memcpy(&tp_message_state[sa_index][da_index][TOTAL_BYTE_INDEX], &msg_size, 2);
      j1939_pgn = (msg.buf[7] << 16) + (msg.buf[6] << 8) + msg.buf[5];
      memcpy(&tp_message_state[sa_index][da_index][PGN_INDEX], &j1939_pgn, 4);
      memset(&tp_messages[sa_index][da_index][0],0xFF,J1939_MAX_LENGTH);
      if (da == self_source_addr){
        // Only respond to things sent to us.
        send_clear_to_send(j1939_pgn,min(total_packets,response_packets),next,sa);
      }
    }
    else if (control_byte == CM_CLEAR_TO_SEND){ //Clear to Send
      uint16_t packets_to_send = msg.buf[1] + (uint16_t(msg.buf[2]) << 8);
      uint8_t start_packet = msg.buf[2];
      j1939_pgn = (msg.buf[7] << 16) + (msg.buf[6] << 8) + msg.buf[5];
      send_multi_frame(da, sa, tp_messages[sa_index][da_index], start_packet, packets_to_send);
    }
    else if (control_byte == CM_END_OF_MESSAGE_ACK){ //End of message ACK

    }
    else if (control_byte == CM_ABORT){ //Abort
      //return 0;
    }  
  }
  
  return dlc; 
}

void send_CMAC_abort(uint8_t sa_index){
  cmac_setup[sa_index] = false;
  CAN_message_t msg;
  sa = (veh_source_addresses[sa_index] & 0x7F) + 0x80;
  msg.len = 2;
  msg.id = 6 << 26 ;
  msg.id += DM18_PGN << 8;
  msg.id += sa << 8; // Destination address
  msg.id += self_source_addr;
  msg.buf[0] = 0;
  msg.buf[1] = 0x0F; // Abort
  //TODO: Add a crypto flag here to be sure 
  Serial.printf("Sending ID %08X ",msg.id);
  print_bytes(msg.buf,msg.len);
  msg.flags.extended = 1;
  vehicle_can.write(msg);
};

void update_cmac(uint8_t cmac_index, CAN_message_t msg) {
  memset(message_for_cmac, 0, sizeof(message_for_cmac));
  memcpy(&message_for_cmac[0], &msg.id, 4);
  message_for_cmac[4] = msg.len;
  memcpy(&message_for_cmac[5], &msg.buf[0], msg.len);
  cmac[cmac_index].update(omac[cmac_index], message_for_cmac, sizeof(message_for_cmac));
}

void send_cmac(uint8_t sa, uint8_t da, uint8_t cmac_index){
//Make a copy to produce an intermediate result
  memcpy(&cmac_copy[cmac_index], &cmac[cmac_index], sizeof(cmac[cmac_index]));
  memcpy(&omac_copy[cmac_index], &omac[cmac_index], sizeof(omac[cmac_index]));
  //Serial.println("CMAC Copy Finalize:");
  cmac_copy[cmac_index].finalize(omac_copy[cmac_index]);
  //print_bytes(omac_copy[i], sizeof(omac_copy[i]));
  CAN_message_t vehicle_msg;
  vehicle_msg.id = 0x00D40000; //DM18 Message with highest priority
  vehicle_msg.id += da << 8;
  vehicle_msg.id += sa;
  vehicle_msg.len = 8;
  vehicle_msg.flags.extended = 1;
  vehicle_msg.buf[0] = 6; //Length
  vehicle_msg.buf[1] = DM18_CMAC_TYPE;
  if (SEQ_MSG) vehicle_msg.seq = 1;
  memcpy(&vehicle_msg.buf[2], &omac_copy[cmac_index], 6);
  vehicle_can.write(vehicle_msg);
  memset(omac[cmac_index],0,sizeof(omac[cmac_index]));
  memcpy(&omac[cmac_index][0], &cmac_counter[cmac_index], 4);
  cmac_counter[cmac_index]++;
  
  //Serial.print("Sent 6 bytes of OMAC: ");
  //print_bytes(vehicle_msg.buf, 6);
}

void compare_cmacs(uint8_t cmac_index, uint8_t *cmac_value) {
  send_cmac(self_source_addr, veh_source_addresses[cmac_index]+0x80, cmac_index);

  if (!memcmp(omac_copy[cmac_index], cmac_value, 6)) {
    cmac_success_counter[cmac_index]++;
    Serial.printf("%8d CMACs for SA %02X Idx %d Matched.\n",cmac_success_counter[cmac_index],veh_source_addresses[cmac_index],cmac_index);
  }
  else {
    cmac_error_counter[cmac_index]++;
    Serial.printf("CMAC %d did not match: %d\n",cmac_index,cmac_error_counter[cmac_index]);
    // Send DM1 Message
    // Send Impostor PG Alert Message

  }
}


void update_DM1_message(uint32_t spn, uint8_t fmi){
  // TODO: Convert this routine to handle long messages and multiple trouble codes.
  Serial.printf("DM1 Message (SPN %d, FMI %d, SA 0x%02X) ",spn,fmi,self_source_addr);
  if (spn == 10841) Serial.print("Impostor PG Source Address, ");
  if (fmi == 19) Serial.print("Received Network Data In Error"); // Received Network Data In Error))
  Serial.println();
  dm1_occurrance_count++;
  if (dm1_occurrance_count > 126) dm1_occurrance_count = 126; // SPN 1216

  dm1_msg.buf[0] = 0b00000100; // LAMP
  dm1_msg.buf[1] = 0b11110011; // Turn on Amber Warning light with slow flash
  dm1_msg.buf[2] = spn & 0xFF; // SPN
  dm1_msg.buf[3] = (spn & 0xFF00) >> 8; // SPN
  dm1_msg.buf[4] = ((spn & 0x70000) >> 11 ) + (fmi & 0b11111); // SPN and FMI (See version 4 in SAE J1939-73)
  dm1_msg.buf[5] = dm1_occurrance_count; // Conversion method and Occurrance Count
  dm1_msg.buf[6] = 255; //10844: Time Since Last Imposter PG Detected
  dm1_msg.buf[7] = 255; //Not used
}
 
void update_pg_alert_msg(const CAN_message_t msg){
  if (impostor_found) return;
  
  impostor_found = true;

  imposter_alert_counter++;
  if (imposter_alert_counter > 250) imposter_alert_counter = 250;
  
  if (imposter_alert_counter <= 1) imposter_timer = 0;

  uint8_t imposter_time = imposter_timer/60000;
  if (imposter_time > 250) imposter_time = 250;
  
  Serial.printf("%3d Impostor PG Alert Message: ",imposter_alert_counter);
  Serial.printf("%08X\n",msg.id);  
 
  dlc = msg.len;
  sa = (msg.id & 0xFF);
  uint32_t pf = (msg.id & 0x3FF0000) >> 16;
  if (pf < 240){
    da = (msg.id & 0x00FF00) >> 8;
    pgn = pf << 8;
  }
  else{
    da = 0xff;  
    pgn = (msg.id & 0x3FFFF00) >> 8;
  }

  impostor_msg.buf[0] = imposter_alert_counter;// 10840: Impostor PG Event Detection Counter
  impostor_msg.buf[1] = sa; //10841: Impostor PG Source Address
  impostor_msg.buf[2] = da;// 10842: Impostor PG Destination Address
  impostor_msg.buf[3] =  pgn & 0x0000FF;// 10843: Impostor PGN - LSB
  impostor_msg.buf[4] = (pgn & 0x00FF00) >> 8;// 10843: Impostor PGN - 2nd Byte
  impostor_msg.buf[5] = (pgn & 0xFF0000) >> 16;// 10843: Impostor PGN - MSB
  impostor_msg.buf[6] = imposter_time; //10844: Time Since Last Imposter PG Detected in minutes
}
 