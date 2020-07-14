# CAN Conditioners and Secure Gateways
Project files to embed cryptographic message authentication data within J1939 and CAN data.

https://www.engr.colostate.edu/~jdaily/CANConditioner/index.html

This repository contains the directories and programs needed to build, provision, and run a cryptgraphic message authentication scheme on a J1939 heavy vehicle network. 

The programs are written in Python 3 or Arduino with the Teensyduino add-on. The primary hardware is the Teensy 4.0 with two CAN channels. The schematic is contained in the *docs* directory. The hardware is the same for both the CAN Conditioners and the Secure Gateway. Each are designed to be installed inline with the J1939 network. 

The core components are:
1. Teensy 4.0 with iMXRT1062 processor
2. Two MCP2562 CAN Transceivers
3. ATECC608A Hardware Security Module

## Directory Summary
*basicPassthrough* A test sketch for ensuring a smooth flow of CAN traffic from one side to another. There are no operations other than passing the data through. 

*CANConditionerSketch* An arduino sketch that generates a CMAC based on the data it receives from the ECU it is protecting. It also implements filtering rules.

*cmac_example* A pair of sketches using Python and Arduino to perform some of the basic cryptographic operations. It is intended to help the programmer debug the code when it comes to working with keys, secrets, signatures, and ciphers.

*docs* A directory that includes schematics, log files, and examples.

*libraries* Common libraries that are used in both the CAN Conditioner and the Secure Gateway. This is an Arduino library and needs to be installed with the rest of the local Arduino Libraries. 

*passthrough_with_simple_attacks* THis sketch is used for testing the system. It is run on the same hardware as the CAN Conditioner or Secure Gateway. The hardware is designed to be a man-in-the-middle for the the J1939.

*provisioningApp* A Python/PyQt5 application to act as a secure bridge between the Arduino Serial commands and the Amazon API Gateway. It requires knowing the API Key and having an account setup with the AWS Cognito userpool dedicated to the CANConditioner.

*provisoningSketch* The Arduino sketch to run on the Teensy during the provisioning process. This sketch uses a heavily modified version of the Sparkfun ATECC library: 
https://github.com/SystemsCyber/SparkFun_ATECCX08a_Arduino_Library/tree/fd25d40105c9d18602365d0eca210c58a714fafd

*serverless* The Python Lambda functions, DynamoDB tables, and API Gateway definitions needed to implement a back-end server using Amazon Web Services. These are used to store the provisioned keys.

*set_eeprom* sketches are the individual source address tables to configure the CAN Conditioners to look for certain messages structures. This should eventually be moved to secure EEPROM in the ATECC chip.

*website* This contains the front-end HTML, Javascript, and JQuery to get users signed up and list the available CAN Conditioners.

## Setup and Provisioning
  1. Build the parts. The board can be purchased from OSH park. There are two variants: 1) D-SUB connectors (indoor), and 2) Deutsch Enclosure (sealed enclosure).

  2. User Registration
https://www.engr.colostate.edu/~jdaily/CANConditioner/login.html
  3. Provision the ATECC608. 
    a. Install the Provisioning Sketch on the Teensy
    b. Run the Provisioning App in Python. You'll have to sign in, have the API Key, and connect the board with a USB Cable. Click on the Provision button to get started. Watch the terminal output for additional information.
  4. Upload the appropriate eeprom sketch.
  5. Upload either the CANConditionerSketch or the InVehicleCryptographicGateway sketch. 

The InVehicleCryptographicGateway sketch is in the private SecureRP1210 repository. It is not in the public domain. However, you could easily build your own.

### API Key
Ask Dr. Daily for the API Key. You'll have to install it as an environment variable. Be sure to restart you command prompt or python environment one the API key is installed. 



### Provisioning Sketch
The Teensy 4.0 needs to use the Wire library to communicate with the ATECC608A.
```
#include <Arduino.h>
#include <i2c_driver_wire.h>
```

## Key Management Strategy
Each device is equipped with an ATECC608A security module. The module needs to be provisioned with its own public/private key pair. Additionally, a server public key needs to be installed and locked on the device. Once the device public key is shared, then the device and server can calculate the same secret and use that shared secret to exchange data.

## Initial Setup
This project uses the Amazon Web Services Key Management System as the root of trust for managing keys. We have requested a Master KMS key.

### KMS Key
Here are the steps taken to create a master key for CANWatermarking. This was already done and does not have to be repeated. This is for reference only. 
  1. Log into console.aws.amazon.com and select the `us-east-1` region.
  2. Select the Key Managment Service (KMS).
  2. Select create key.
  3. Select symmetric key.
  4. On the Add Labels step, set the Alias to `CANWatermarkingKey`.
  5. Add a tag if desired.
  6. Set who can administer the key.
  7. Once finished, you should have a customer master key (CMK) called the CANWatermarkingKEY.
  8. The key will have an ARN, which is something like this: `arn:aws:kms:us-east-1:000000000000:key/aaaaaaaa-bbbb-cccc-dddd-111111111111` where the last part is the key id.

 We now have a hardware protected AES-256-GCM master key that will keep all of our other secrets safe. These other secrets are the device key materials. 

### API Gateway
The API Gateway and Lambda Functions are deployed using the serverless architecture.

From a Linux machine, setup the serverless architecture for AWS.

Deploy the system by running `sls deploy` in the serverless directory.

If it doesn't work, you probably need to setup your credentials and serverless system.

The serverless architecture deploys the API gateway and the Cognito User pool.

Under Cognito -> User Pools -> CANConditionerUsers -> General Settings -> App clients, select Enable username password based authentication

