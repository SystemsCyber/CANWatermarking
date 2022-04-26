import json
import base64
import random
import string
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr

from utils import lambdaResponse as response

region = 'us-east-1'

os.environ['AdminSecretKey']= 'lRz4eNBQbObc5absat+To6u/keRlj8/6IbQAu6h9'
os.environ['AdminAccessKeyId']= 'AKIARNA4VTG7D7GXMJJR'

def get_key(event,context):
    """
    Read post data to create a new key based on a new device
    """
    # Check Authorization
    requester_data = event["requestContext"]
    if requester_data["authorizer"]["claims"]["email_verified"]:
        identity_data = event["requestContext"]["identity"]
        ip_address = identity_data["sourceIp"]
        email = requester_data["authorizer"]["claims"]["email"].lower()
    else:
        return response(400, "Email not verified.")
    
    body = json.loads(event['body'])
    try: 
        assert 'serial_number' in body
    except AssertionError:
        return response(400, "Missing required parameters.")
    print(body['serial_number'])
    try:
        serial_number = body['serial_number']
        assert len(serial_number) == 18
    except:
        return response(400, "Parameters are in the incorrect format.")
    

    key_dict = decrypt_device_key(serial_number)
    
    if key_dict is None:
        return response(400, 'There was a problem getting device keys. Is this device provisioned?')
    
    # if roll_device_key_password(serial_number):
    #     print('Reset User Passcode')
    # else:
    #     return response(400,"Failed to roll new key")
    
    return response(200, key_dict)

def shared_secret(event,context):
    """
    Read post data to create a new key based on a new device
    """
    # Check Authorization
    requester_data = event["requestContext"]
    if requester_data["authorizer"]["claims"]["email_verified"]:
        identity_data = event["requestContext"]["identity"]
        ip_address = identity_data["sourceIp"]
        email = requester_data["authorizer"]["claims"]["email"].lower()
    else:
        return response(400, "Email not verified.")
    
    body = json.loads(event['body'])
    try: 
        assert 'serial_number' in body
    except AssertionError:
        return response(400, "Missing required parameters.")
    print(body['serial_number'])
    try:
        serial_number = body['serial_number']
        assert len(serial_number) == 18
    except:
        return response(400, "Parameters are in the incorrect format.")
    
    admin_user = True
    key_dict = decrypt_device_key(serial_number, admin_user)
    
    if key_dict is None:
        return response(400, 'There was a problem getting device keys. Is this device provisioned?')
    
    server_pem_key_pass = key_dict['server_private_key'].encode('ascii')
    full_password =  base64.b64decode(key_dict['full_password'])

    server_private_key = serialization.load_pem_private_key(server_pem_key_pass, 
                                                            password=full_password, 
                                                            backend=default_backend())
    
    #Serialize server private key with password from full_password
    server_pem_key = server_private_key.private_bytes(
                                encoding = serialization.Encoding.PEM,
                                format = serialization.PrivateFormat.PKCS8,
                                encryption_algorithm = serialization.NoEncryption())
    device_pub_key_bytes = base64.b64decode(key_dict['device_pub_key'])
    device_bytes = b'\x04' + device_pub_key_bytes #This makes DER keys
    device_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),
                                                                      device_bytes)
    shared_secret = base64.b64encode(server_private_key.exchange(ec.ECDH(),device_pub_key)[:16]).decode('ascii')

    return response(200, {'server_pem_key':server_pem_key.decode('ascii'), 
                          'shared_secret': shared_secret})

def list_keys(event,context):
    """
    Read post data to create a new key based on a new device
    """
    # Check Authorization
    requester_data = event["requestContext"]
    if requester_data["authorizer"]["claims"]["email_verified"]:
        identity_data = event["requestContext"]["identity"]
        ip_address = identity_data["sourceIp"]
        email = requester_data["authorizer"]["claims"]["email"].lower()
    else:
        return response(400, "Email not verified.")
    print(email)

    dbClient = boto3.resource('dynamodb', region_name='us-east-1')
    table = dbClient.Table("CANConditioners")
    
    db_response = table.scan()
    data = db_response['Items']
    while 'LastEvaluatedKey' in db_response:
        db_response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
        data.extend(db_response['Items'])
    print(data)

    return response(200, data)

def decrypt_data_key(data_key_encrypted):
    """Decrypt an encrypted data key

    :param data_key_encrypted: Encrypted ciphertext data key.
    :return Plaintext base64-encoded binary data key as binary string
    :return None if error
    """

    # Decrypt the data key
    kms_client = boto3.client('kms', 
                              region_name='us-east-1',
                              aws_access_key_id = os.environ['AdminAccessKeyId'],
                              aws_secret_access_key = os.environ['AdminSecretKey'])
    try:
        response = kms_client.decrypt(CiphertextBlob=data_key_encrypted)
    except ClientError as e:
        print(e)
        return None

    # Return plaintext base64-encoded binary data key
    return base64.b64encode((response['Plaintext']))

def decrypt_device_key(serial_number, admin_user=False):
    
    dbClient = boto3.resource('dynamodb', 
                              region_name='us-east-1',
                              aws_access_key_id = os.environ['AdminAccessKeyId'],
                              aws_secret_access_key = os.environ['AdminSecretKey'])
    table = dbClient.Table("CANConditioners")
    #try:
    item = table.get_item( 
            Key = {'id': serial_number,} 
        ).get('Item')
    # except:
    #     print("Unable to retrieve serial number from table.")
    #     return

    if item is None:
        print("Unable to retrieve serial number from table.")
        return
        
    # Decrypt the data key before using it
    cipher_key = base64.b64decode(item['encrypted_data_key'])
    data_key_plaintext = decrypt_data_key(cipher_key)
    if data_key_plaintext is None:
        print("Data Key is Not Available")
        return
    

    # Decrypt the private key for the device
    f = Fernet(data_key_plaintext)
    device_code = f.decrypt(base64.b64decode(item['encrypted_device_code'])).decode('ascii') #This was padded with zeros
    print('device_code = {}'.format(device_code) )
    server_pem_key_pass = f.decrypt(base64.b64decode(item['encrypted_server_pem_key']))
    print('server_pem_key_pass = {}'.format(server_pem_key_pass) )
    device_password = f.decrypt(base64.b64decode(item['encrypted_device_password'])).decode('ascii')
    print('device_password = {}'.format(device_password))
    full_password = f.decrypt(base64.b64decode(item['encrypted_key_code']))
    print('full_password = {}'.format(full_password))
    device_pub_key = f.decrypt(base64.b64decode(item['encrypted_device_public_key']))
    print('device_pub_key = {}'.format(device_pub_key))

    key_dict = {
        'id': serial_number,
        'server_private_key': server_pem_key_pass.decode('ascii'),
        'device_password': device_password, #we may want to e-mail this out.
        'device_code': device_code, 
        'server_pem_key_pass': server_pem_key_pass
        
    }
    if admin_user == True:
        key_dict['full_password'] = base64.b64encode(full_password).decode('ascii')
        key_dict['device_pub_key'] = base64.b64encode(device_pub_key).decode('ascii')
    
    return key_dict    

def roll_device_key_password(serial_number):

    print("Rolling Device Key password")
    key_dict = decrypt_device_key(serial_number, admin_user=True)
    full_password = key_dict['full_password']

    print("Old Device full_password = ", full_password)
    choices = string.ascii_letters + string.digits
    new_device_password = ''.join(random.choices(choices,k=8)).encode('ascii')
    new_full_password = new_device_password + full_password[8:24]
    assert len(new_full_password) == 24
    print("New Device full_password = ", new_full_password)

    server_private_key = serialization.load_pem_private_key(server_pem_key_pass, 
                                                            password=full_password, 
                                                            backend=default_backend())
    
    #Serialize server private key with password from full_password
    new_server_pem_key_pass = server_private_key.private_bytes(
                                encoding = serialization.Encoding.PEM,
                                format = serialization.PrivateFormat.PKCS8,
                                encryption_algorithm = serialization.BestAvailableEncryption(new_full_password))
    
    # Encrypt the file
    encrypted_server_pem_key = base64.b64encode(f.encrypt(new_server_pem_key_pass))
    encrypted_device_password = base64.b64encode(f.encrypt(new_device_password))
    encrypted_key_code = base64.b64encode(f.encrypt(new_full_password))
    
    dbClient = boto3.resource('dynamodb', region_name=region)
    table = dbClient.Table("CANConditioners")
    try:
        ret_dict = table.update_item(
                Key = {'id':serial_number},
                UpdateExpression = 'SET encrypted_server_pem_key= :val1, encrypted_key_code= :val2, encrypted_device_password= :val3',
                ExpressionAttributeValues = {':val1': str(encrypted_server_pem_key,'ascii'),
                                             ':val2': str(encrypted_key_code,'ascii'),   
                                             ':val3': str(encrypted_device_password,'ascii')}
            )
    except ClientError as e:
        print(e)
        return False
    return(True)

if __name__ == '__main__':
    ids= ["0123308F0B3BD236EE",
          "01232701F2E7A649EE",
          "012395F827E2BED6EE",
          "0123C1B81F68E4C9EE",
          "0123E81CF6720C1CEE",
          "01231017636F64B4EE",
          "0123364B5F74E501EE",
          "01239F151E138F42EE",
          "0123B334337CD440EE",
          "01231346759CD71BEE",
          "0123B9753679B913EE",
          "0123DC96321F7FAEEE",
          "012374B9754CBE4EEE",
          "0123716DB252F46CEE",
          "012362826474A4F4EE",
          "0123B75EF1F75703EE",
          "01233F098FD2694AEE",
          "0123982154E9289EEE",
          "01237C34D3A31BBAEE",
          "01236494726CDF59EE",
          "01237482C2910B18EE",
          "012304D2E9253891EE",
          "0123345D586AD20EEE"]
    results = []
    for sn in ids:
        key_dict = decrypt_device_key(sn, admin_user=True)
        print(key_dict)
        server_pem_key_pass = key_dict['server_pem_key_pass']
        full_password =  base64.b64decode(key_dict['full_password'])
        server_private_key = serialization.load_pem_private_key(server_pem_key_pass, 
                                                            password=full_password, 
                                                            backend=default_backend())
    
        #Serialize server private key with password from full_password
        new_server_pem_key_pass = server_private_key.private_bytes(
                                encoding = serialization.Encoding.PEM,
                                format = serialization.PrivateFormat.PKCS8,
                                encryption_algorithm = serialization.NoEncryption())
    
        key_dict['server_pem_key_pass'] = new_server_pem_key_pass.decode('ascii')
        #Serialize server private key with password from full_password
        device_pub_key_bytes = base64.b64decode(key_dict['device_pub_key'])
        #device_pub_key_bytes = bytes(bytearray.fromhex(pub_key.decode('utf-8')))
        assert len(device_pub_key_bytes) == 64
        key_dict['device_pub_key_ascii'] = "".join(["{:02X}".format(b) for b in device_pub_key_bytes])
        device_bytes = b'\x04' + device_pub_key_bytes #This makes is a DER keys
        device_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),
                                                                      device_bytes)

        shared_secret = base64.b64encode(server_private_key.exchange(ec.ECDH(),device_pub_key)[:16]).decode('ascii')

        device_pub_key_pem = device_pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
        key_dict['device_pub_key_pem'] = device_pub_key_pem.decode('ascii')
        key_dict['shared_secret'] = shared_secret
        results.append(key_dict)

    with open("key_file.json", 'w') as f:
        json.dump(results,f, sort_keys=True, indent=4)