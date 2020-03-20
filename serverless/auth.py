import json
import base64
import time

import boto3
from botocore.exceptions import ClientError

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from utils import lambdaResponse as response
from utils import get_timestamp
region = 'us-east-1'

def auth(event, context):
    """
    Return the plain text session key used to encrypt the CAN Data File
    
    event dictionary input elements:
     - CAN Conditioner Serial Number
     - Encrypted data

    Prerequisites:
    The CAN Conditioner must be provisioned with a securely stored key tied to the
    serial number.
    """
    #Determine the identity of the requester.
    requester_data = event["requestContext"]
    if requester_data["authorizer"]["claims"]["email_verified"]:
        identity_data = event["requestContext"]["identity"]
        ip_address = identity_data["sourceIp"]
        email = requester_data["authorizer"]["claims"]["email"].lower()
    else:
        return response(400, "Email not verified.")

    #Check if email is the uploader or has share access
    if not email in item['uploader'] and not email in item['access_list']:
        return response(400, "You do not have permission to decrypt.")
  
    #load the event body into a dictionary
    body = json.loads(event['body'])

    # Test to be sure the necessary elements are present
    try: 
        assert 'serial_number' in body
        assert 'encrypted_session_key' in body
    except AssertionError:
        return response(400, "Missing required parameters.")
   
    # Lookup the data needed from the unique CAN Logger by its serial number
    dbClient = boto3.resource('dynamodb', region_name=region)
    table = dbClient.Table("CANConditioners")
    try:
        item = table.get_item( 
            Key = {'id': body['serial_number'],} 
        ).get('Item')
    except:
        return response(400, "Unable to retrieve table item.")
    
    # load the device's public key which was stored as a base64 encoded binary
    device_public_key_bytes = base64.b64decode(item['device_public_key']).decode('ascii')
    device_bytes = b'\x04' + device_public_key_bytes
    device_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),device_bytes)
    
    # Decrypt the data key before using it
    cipher_key = base64.b64decode(item['encrypted_data_key'])
    data_key_plaintext = decrypt_data_key(cipher_key)
    if data_key_plaintext is None:
        return response(400, "Data Key is Not Available")

    # Decrypt the private key for the device
    f = Fernet(data_key_plaintext)
    decrypted_pem = f.decrypt(base64.b64decode(item['encrypted_server_pem_key']))
    
    #load the serialized key into an object
    server_key = serialization.load_pem_private_key(decrypted_pem, 
                                                    password=None, 
                                                    backend=default_backend())
    #Derive shared secret
    shared_secret = server_key.exchange(ec.ECDH(),device_public_key)
  
    #use the first 16 bytes (128 bits) of the shared secret to decrypt the session key
    cipher = Cipher(algorithms.AES(shared_secret[:16]), 
                                   modes.ECB(), 
                                   backend=default_backend())
    decryptor = cipher.decryptor()
    clear_key = decryptor.update(session_key) + decryptor.finalize()
    
    # set attribution data
    timestamp = get_timestamp(time.time())
    access_tuple = str((timestamp, email, ip_address))
    print("Access Tuple: {}".format(access_tuple))
    download_list = item["download_log"]
    download_list.append(access_tuple)

    #update the download log with the user details. Keep the last 100 access tuples
    table.update_item(
        Key = {'digest':body['digest']},
        UpdateExpression = 'SET download_log= :var',
        ExpressionAttributeValues = {':var':download_list[-100:]},
        )

    #return the string base64 encoded AES key for that session.
    return response(200, base64.b64encode(clear_key).decode('ascii'))
    
def decrypt_data_key(data_key_encrypted):
    """Decrypt an encrypted data key

    :param data_key_encrypted: Encrypted ciphertext data key.
    :return Plaintext base64-encoded binary data key as binary string
    :return None if error
    """

    # Decrypt the data key
    kms_client = boto3.client('kms', region_name=region)
    try:
        response = kms_client.decrypt(CiphertextBlob=data_key_encrypted,
                                      KeyId='alias/CANWatermarkingKey',)
    except ClientError as e:
        print(e)
        return None

    # Return plaintext base64-encoded binary data key
    return base64.b64encode((response['Plaintext']))