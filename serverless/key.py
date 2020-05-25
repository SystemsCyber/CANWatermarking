import json
import base64
import random
import string

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr

from utils import lambdaResponse as response

region = 'us-east-1'


def get_key(event, context):
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


def shared_secret(event, context):
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
    full_password = base64.b64decode(key_dict['full_password'])

    server_private_key = serialization.load_pem_private_key(server_pem_key_pass,
                                                            password=full_password,
                                                            backend=default_backend())

    # Serialize server private key with password from full_password
    server_pem_key = server_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    device_pub_key = base64.b64decode(key_dict['device_pub_key'])
    shared_secret = base64.b64encode(server_private_key.exchange(ec.ECDH(), device_pub_key)[:16]).decode('ascii')

    return response(200, {'server_pem_key': server_pem_key.decode('ascii'),
                          'shared_secret': shared_secret})


def list_keys(event, context):
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
    kms_client = boto3.client('kms')
    try:
        response = kms_client.decrypt(CiphertextBlob=data_key_encrypted)
    except ClientError as e:
        print(e)
        return None

    # Return plaintext base64-encoded binary data key
    return base64.b64encode((response['Plaintext']))


def decrypt_device_key(serial_number, admin_user=False):
    dbClient = boto3.resource('dynamodb', region_name='us-east-1')
    table = dbClient.Table("CANConditioners")
    try:
        item = table.get_item(
            Key={'id': serial_number, }
        ).get('Item')
    except:
        print("Unable to retrieve serial number from table.")
        return

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
    device_code = f.decrypt(base64.b64decode(item['encrypted_device_code'])).decode(
        'ascii')  # This was padded with zeros
    print('device_code = {}'.format(device_code))
    server_pem_key_pass = f.decrypt(base64.b64decode(item['encrypted_server_pem_key']))
    print('server_pem_key_pass = {}'.format(server_pem_key_pass))
    device_password = f.decrypt(base64.b64decode(item['encrypted_device_password'])).decode('ascii')
    print('device_password = {}'.format(device_password))
    full_password = f.decrypt(base64.b64decode(item['encrypted_key_code']))
    print('full_password = {}'.format(full_password))
    device_pub_key = f.decrypt(base64.b64decode(item['encrypted_device_public_key']))
    print('device_pub_key = {}'.format(device_pub_key))

    key_dict = {
        'id': serial_number,
        'server_private_key': server_pem_key_pass.decode('ascii'),
        'device_password': device_password,  # we may want to e-mail this out.
        'device_code': device_code,

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
    new_device_password = ''.join(random.choices(choices, k=8)).encode('ascii')
    new_full_password = new_device_password + full_password[8:24]
    assert len(new_full_password) == 24
    print("New Device full_password = ", new_full_password)

    server_private_key = serialization.load_pem_private_key(server_pem_key_pass,
                                                            password=full_password,
                                                            backend=default_backend())

    # Serialize server private key with password from full_password
    new_server_pem_key_pass = server_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(new_full_password))

    # Encrypt the file
    encrypted_server_pem_key = base64.b64encode(f.encrypt(new_server_pem_key_pass))
    encrypted_device_password = base64.b64encode(f.encrypt(new_device_password))
    encrypted_key_code = base64.b64encode(f.encrypt(new_full_password))

    dbClient = boto3.resource('dynamodb', region_name=region)
    table = dbClient.Table("CANConditioners")
    try:
        ret_dict = table.update_item(
            Key={'id': serial_number},
            UpdateExpression='SET encrypted_server_pem_key= :val1, encrypted_key_code= :val2, encrypted_device_password= :val3',
            ExpressionAttributeValues={':val1': str(encrypted_server_pem_key, 'ascii'),
                                       ':val2': str(encrypted_key_code, 'ascii'),
                                       ':val3': str(encrypted_device_password, 'ascii')}
        )
    except ClientError as e:
        print(e)
        return False
    return (True)