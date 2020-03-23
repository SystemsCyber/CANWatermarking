import json
import base64
import hashlib
import random
import string

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec,rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import boto3
from botocore.exceptions import ClientError

from utils import lambdaResponse as response


region = 'us-east-1'

def provision(event,context):
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
        assert 'device_public_key' in body
    except AssertionError:
        return response(400, "Missing required parameters.")
    try:
        pub_key = base64.b64decode(body['device_public_key'])
        assert len(pub_key) == 128
        device_pub_key_bytes = bytes(bytearray.fromhex(pub_key.decode('utf-8')))
        assert len(device_pub_key_bytes) == 64
        serial_number = str(base64.b64decode(body['serial_number']),'ascii')
        assert len(serial_number) == 18
    except:
        return response(400, "Parameters are in the incorrect format.")
    
    #generate server RSA key pair
    rsa_private_key = rsa.generate_private_key(public_exponent=65537,
                                               key_size=2048,
                                               backend=default_backend())
    rsa_public_key = rsa_private_key.public_key()
    rsa_public_key_der = rsa_public_key.public_bytes(
        encoding = serialization.Encoding.DER,
        format = serialization.PublicFormat.PKCS1)

    #generate server ECC key pair
    server_private_key = ec.generate_private_key(ec.SECP256R1(), 
                                                 default_backend())
    server_public_key = server_private_key.public_key()
    server_public_key_bytes = server_public_key.public_bytes(
        encoding = serialization.Encoding.X962,
        format = serialization.PublicFormat.UncompressedPoint)[1:]
  
    #Hash device public key and server public key for manual verification
    device_public_key_hash = hashlib.sha256(device_pub_key_bytes).digest()
    server_public_key_hash = hashlib.sha256(server_public_key_bytes).digest()
    print('device_public_key_hash: ', device_public_key_hash.hex().upper())
    print('server_public_key_hash: ', server_public_key_hash.hex().upper())

    #digitally sign the RSA public key as a DER encoded signature per RFC 3279
    rsa_public_key_signature = server_private_key.sign(bytes(rsa_public_key_der),
                                                       ec.ECDSA(hashes.SHA256()))

    #Create random 16 bytes for the PEM key
    choices = string.ascii_letters + string.digits
    device_password = b''
    device_code = b'\x00'*8
    for i in range(8):
        device_password += bytes(random.choice(choices),'utf-8')
        device_code += bytes(random.choice(choices),'utf-8')
    
    #Load Device Public Key and derive shared secret
    device_bytes = b'\x04' + device_pub_key_bytes
    #print('device_bytes:')
    #print(device_bytes)
    try:
        device_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),
                                                                      device_bytes)
    except ValueError:
        return response(400, "Device Public Key is malformed")
    shared_secret = server_private_key.exchange(ec.ECDH(),device_pub_key)

    #use the first 16 bytes (128 bits) of the shared secret to encrypt the random password
    cipher = Cipher(algorithms.AES(shared_secret[:16]), 
                                   modes.ECB(), 
                                   backend=default_backend())
    encryptor = cipher.encryptor()
    assert len(device_code) == 16
    encrypted_device_code = encryptor.update(device_code) + encryptor.finalize()
    
    # Put together the 24 bytes needed for the key
    rand_pass = device_password + encrypted_device_code
    assert len(rand_pass) == 24

    #Serialize server private key with password from rand_pass
    server_pem_key_pass = server_private_key.private_bytes(
                            encoding = serialization.Encoding.PEM,
                            format = serialization.PrivateFormat.PKCS8,
                            encryption_algorithm = serialization.BestAvailableEncryption(rand_pass))

    #Serialize server private key with password from rand_pass
    server_rsa_key_pass = rsa_private_key.private_bytes(
                            encoding = serialization.Encoding.PEM,
                            format = serialization.PrivateFormat.PKCS8,
                            encryption_algorithm = serialization.BestAvailableEncryption(rand_pass))

    # Generate a data key associated with the CMK
    # The data key is used to encrypt the file. Each file can use its own
    # data key or data keys can be shared among files.
    encrypted_data_key, data_key_plaintext = create_data_key()
    if encrypted_data_key is None:
        return response(400, "Data key not created.")
    
    
    # Encrypt the file
    f = Fernet(data_key_plaintext)
    encrypted_server_pem_key = f.encrypt(server_pem_key_pass)
    encrypted_device_public_key = f.encrypt(device_pub_key_bytes)
    encrypted_device_password = f.encrypt(device_password)
    encrypted_device_code = f.encrypt(device_code[8:16]) #This was padded with zeros
    encrypted_key_code = f.encrypt(rand_pass)

    can_conditioner_dict = {
        'id': serial_number, #72 bit unique id from the ATECC608.
        'email': email,
        'sourceIp': ip_address,
        'encrypted_device_public_key': str(base64.b64encode(encrypted_device_public_key),'ascii'),
        'encrypted_data_key': str(base64.b64encode(encrypted_data_key),'ascii'),
        'encrypted_server_pem_key': str(base64.b64encode(encrypted_server_pem_key),'ascii'),
        'encrypted_device_password': str(base64.b64encode(encrypted_device_password),'ascii'),
        'encrypted_device_code': str(base64.b64encode(encrypted_device_code),'ascii'),
        'encrypted_key_code': str(base64.b64encode(encrypted_key_code),'ascii'),

    }

    #Load the server_public_key, the server_pem_key_pass, and the encrypted_rand_pass
    data_dict = {
    	'id': serial_number,
        'rsa_public_key': str(base64.b64encode(rsa_public_key_der),'ascii'),
        'rsa_public_key_signature': str(base64.b64encode(rsa_public_key_signature),'ascii'),
        'server_public_key': str(base64.b64encode(server_public_key_bytes),'ascii'),
        'device_password': str(base64.b64encode(device_password),'ascii'),
        'device_code': str(base64.b64encode(device_code[8:16]),'ascii'),
        'device_public_key_prov_hash': device_public_key_hash.hex().upper(),
        'server_public_key_prov_hash': server_public_key_hash.hex().upper(),
    }
    
    
    dbClient = boto3.resource('dynamodb', region_name=region)
    table = dbClient.Table("CANConditioners")
    try:
        ret_dict = table.put_item(
                Item = can_conditioner_dict,
                ConditionExpression = 'attribute_not_exists(id)'
            )
    except ClientError as e:
        print(e)
        return response(400, "Database entry failed. The serial number may already exist.")
    return response(200, data_dict)
    

def create_data_key():
    """Generate a data key to use when encrypting and decrypting data

    :param cmk_id: KMS CMK ID or ARN under which to generate and encrypt the
    data key.
    :param key_spec: Length of the data encryption key. Supported values:
        'AES_128': Generate a 128-bit symmetric key
        'AES_256': Generate a 256-bit symmetric key
    :return Tuple(EncryptedDataKey, PlaintextDataKey) where:
        EncryptedDataKey: Encrypted CiphertextBlob data key as binary string
        PlaintextDataKey: Plaintext base64-encoded data key as binary string
    :return Tuple(None, None) if error
    """

    # Create data key
    kms_client = boto3.client('kms',region_name=region)
    try:
        data_response = kms_client.generate_data_key(KeyId='alias/CANWatermarkingKey',
                                                     KeySpec='AES_256')
    except ClientError as e:
        print(e)
        return None, None

    # Return the encrypted and plaintext data key
    return data_response['CiphertextBlob'], base64.b64encode(data_response['Plaintext'])   