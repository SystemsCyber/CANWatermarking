# CANWatermarking
Project files to embed cryptographic message authentication data within J1939 and CAN data.

## Key Management Strategy
Each device is equipped with an ATECC608A security module. The module needs to be provisioned with its own public/private key pair. Additionally, a server public key needs to be installed and locked on the device. Once the device public key is shared, then the device and server can calculate the same secret and use that shared secret to exchange data.


## Initial Setup
This project uses the Amazon Web Services Key Management System as the root of trust. We have requested a Master KMS key.

### KMS Key
Here are the steps taken to create a master key for CANWatermarking.
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

### User Registration
https://can-conditioner.s3-website-us-east-1.amazonaws.com/index.html
