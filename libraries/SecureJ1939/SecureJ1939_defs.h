#define CMAC_BLOCK_SIZE             512
#define AES_BLOCK_SIZE              16
#define NUM_SOURCE_ADDRESSES        24 
#define NUM_ECU_SOURCE_ADDRESSES    2
#define NUM_DESTINATION_ADDRESSES   1+2*NUM_ECU_SOURCE_ADDRESSES // Global and Self*2

#ifndef SEQ_MSG
#define SEQ_MSG true
#endif

#define EEPROM_NUM_ECU_SA_ADDR    161
#define EEPROM_ECU_LENGTH         24
#define EEPROM_ECU_ADDR           162
#define EEPROM_NUM_VEH_SA_ADDR    186
#define EEPROM_VEH_LENGTH         24
#define EEPROM_VEH_ADDR           187

#define EEPROM_SELF_SOURCE_ADDR   160

#define SA_MASK 0x000000FF

#define DM18_PGN                  54272
#define DM18_PUBLIC_KEY_TYPE      0x04
#define DM18_CMAC_TYPE            0x05
#define DM18_SESSION_KEY          0x02
#define DM18_CONFIRMATION_TYPE    0x06
#define DM18_RESET_TYPE           0x0F
#define COMPONENT_ID_PGN          65259
#define REQUEST_PGN               59904
#define TP_DT_PGN                 60160
#define TP_CM_PGN                 60416
#define CM_END_OF_MESSAGE_ACK     19
#define CM_CLEAR_TO_SEND          17
#define CM_REQUEST_TO_SEND        16
#define CM_BAM                    32
#define CM_ABORT                  255

#define DATA_SECURITY_PGN         54272
#define DATA_SECURITY_LONG_SEED   0x00
#define DATA_SECURITY_LONG_KEY    0x01
#define DATA_SECURITY_SESSION_KEY 0x02
#define DATA_SECURITY_CERTIFICATE 0x03
#define DATA_SECURITY_PUBLIC_KEY  0x04
#define DATA_SECURITY_CMAC        0x05
#define DATA_SECURITY_SERIAL_NUM  0x0C

#define NORMAL_PRIORITY 6
#define GLOBAL_ADDR     255
#define GATEWAY_SOURCE_ADDR  37

#define J1939_MAX_LENGTH 1785

#define PACKET_COUNTER_INDEX 0
#define TOTAL_COUNT_INDEX    1
#define TOTAL_BYTE_INDEX     2 //Takes 2 bytes
#define PGN_INDEX            4 //Takes 4 bytes
#define BAM_CTS_RTS_INDEX    8
#define COUNT_TO_SEND_INDEX  9

#define BAM_TYPE             0
#define CTS_RTS_TYPE         1

#define IMPOSTOR_PG_ALERT_PGN           61839
// Suspect Parameter Numbers
#define IMPOSTOR_PG_SOURCE_ADDRESS      10841
#define IMPOSTOR_PG_DESTINATION_ADDRESS 10842
#define IMPOSTOR_PGN                    10842
#define TIME_SINCE_LAST_PG_DETECTED     10842
#define DATA_SECURITY_PARAMETER 		1597
#define ENCRYPTION_SEED_INDICATOR       1194
#define PASSWORD_VALID_INDICATOR        1195
#define RANDOM_NUMBER_INDICATOR         1198
#define PASSWORD_REPRESENTATION         1202

// Failure Mode Indicators for DM1 messages
#define RECEIVED_NETWORK_DATA_IN_ERROR      19
#define ABNORMAL_UPDATE_RATE                9
#define BAD_INTELLIGENT_DEVICE              12
#define OUT_OF_CALIBRATION                  13
#define SPECIAL_INSTRUCTIONS                14
#define DATA_INCORRECT                      2

#define DM1_MESSAGE_TIMEOUT         1000
#define IMPOSTOR_PG_MESSAGE_TIMEOUT 1000

#define MESSAGE_TIMEOUT 250 //milliseconds

uint8_t self_source_addr;
uint8_t num_ecu_source_addresses;
uint8_t num_veh_source_addresses;
uint8_t ecu_source_addresses[NUM_SOURCE_ADDRESSES];
uint8_t veh_source_addresses[NUM_SOURCE_ADDRESSES];