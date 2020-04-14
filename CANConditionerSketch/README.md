## Example CAN Bus Output
The following transcript was taken of a CAN Conditioner exchanging a key with a Secure Gateway
The data was recorded uing the can-utils from SocketCAN built into a BeagleBone Black.
In this example, Source Address 0x88 is the CAN Conditioner and Source Address 0x25 is the Secure Gateway.

Sending a public key from the CAN Conditioner to the Secure Gateway. We are using the J1939 transport protocol. 
The parameter group number is 0xD400, which is for Data Security. There are 64 bytes for the P256 Elliptic Curve Public Key; however,
66 bytes are sent because the first two bytes are the length and type, respectively.

```
can1  18EC2588   [8]  20 42 00 0A FF 00 D4 00
can1  18EB2588   [8]  01 40 04 DE 5A 1C 60 F5
can1  18EB2588   [8]  02 5C 81 57 98 37 28 D6
can1  18EB2588   [8]  03 9A 1F 40 30 4E FE FC
can1  18EB2588   [8]  04 2F 9E B5 2F 8C DD AB
can1  18EB2588   [8]  05 01 F5 C0 2D 08 ED F3
can1  18EB2588   [8]  06 6D 05 24 B9 1C 45 88
can1  18EB2588   [8]  07 5B 4D 1B 55 9B 82 F0
can1  18EB2588   [8]  08 95 89 BA 5C 6E F9 1C
can1  18EB2588   [8]  09 6F BB 7C 0C 2F 38 5A
can1  18EB2588   [8]  0A 5C 9E 5B 00 00 F8 0E
```
  
The Gateway responds with it's public key. Now both devices have a public key and can compute a shared secret. 
Note: anyone can create this key, so we should follow it with a signature that matches a signature key securely stored on the devices. 

```
can1  18EC8825   [8]  20 42 00 0A FF 00 D4 00
can1  18EB8825   [8]  01 40 04 CC 48 66 43 B3
can1  18EB8825   [8]  02 B1 65 4A 62 26 03 E4
can1  18EB8825   [8]  03 7B AD 93 43 B5 05 91
can1  18EB8825   [8]  04 B9 F7 32 D0 DC E6 3A
can1  18EB8825   [8]  05 39 A8 04 A3 F1 2D 14
can1  18EB8825   [8]  06 82 CF 9B 71 5F 06 30
can1  18EB8825   [8]  07 A2 0B FE D8 80 68 81
can1  18EB8825   [8]  08 6B F2 7E 16 7C DD 11
can1  18EB8825   [8]  09 8F 05 B8 AE A1 0E 96
can1  18EB8825   [8]  0A DB B5 7E 00 20 1C C2
```

The CAN Conditioner produces a NONCE, then envelope encrypts the Nonce with the ECDH derived secret key. 
This is the encrypted session key that is transmitted over CAN to the Secure Gateway.  The message is split with the first
16 bytes representing the encrypted session key and the last 10 bytes are a random seed (initialization vector).

```
can1  18EC2588   [8]  20 1C 00 04 FF 00 D4 00
can1  18EB2588   [8]  01 1A 02 4C 77 FA AD 6F
can1  18EB2588   [8]  02 DF D4 AE 6F 71 9D 71
can1  18EB2588   [8]  03 01 E9 D0 64 42 54 8C
can1  18EB2588   [8]  04 39 44 01 44 6A E0 C5
```

The Secure Gateway decrypts the session key sent by the CAN Conditioner and encrypts the random seed sent with the last packet. 
The encrypted seed is sent back to the CAN Conditioner. Since the seed was only 10 bytes, it is padded with 6 zeros before being encrypted.

```
can1  18EC8825   [8]  20 12 00 03 FF 00 D4 00
can1  18EB8825   [8]  01 10 06 9F 75 6A 99 BC
can1  18EB8825   [8]  02 51 86 32 6F C4 E7 8F
can1  18EB8825   [8]  03 69 CB 98 97 00 20 00
```
  
The CAN Conditioner now knows the gateway is ready to receive CMAC messages. The following message gets sent out periodically. The Gateway can calculate its own CMAC and compare the first 6 bytes to the transmitted shown. 

``` 
can1  18D42588   [8]  06 05 99 2C 83 AE FC 9D
```

A short time later:

```
can1  18D42588   [8]  06 05 81 41 2F 84 47 13
```
