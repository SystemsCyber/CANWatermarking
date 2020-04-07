from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
#slot0
#Add 04 to the beginning
device_pub = '04 A7 2C 24 D6 0A 1A 0B 82 7C DC 3B 48 A0 7A FB 6D 8B E5 6E 3F 69 33 D9 10 31 5E BB 69 ED A2 BA 3B AB C6 AB 92 AF E8 79 4B B7 91 3F 56 06 84 A3 73 8F 41 84 F4 E4 9F 2F CC B4 83 58 E5 BB B1 57 93'
device_bytes = bytes.fromhex(device_pub)
device_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),device_bytes)
#generate server ECC key pair
# server_private_key = ec.generate_private_key(ec.SECP256R1(), 
#                                              default_backend())
# server_pem_key = server_private_key.private_bytes(
#                             encoding = serialization.Encoding.PEM,
#                             format = serialization.PrivateFormat.PKCS8,
#                             encryption_algorithm = serialization.NoEncryption() )
# with open('private.pem','wb') as f:
# 	f.write(server_pem_key)

with open('private.pem','rb') as f:
 	server_pem_key = f.read()
server_private_key = serialization.load_pem_private_key(server_pem_key,password=None, backend=default_backend())

server_public_key = server_private_key.public_key()
server_public_key_bytes = server_public_key.public_bytes(
    encoding = serialization.Encoding.X962,
    format = serialization.PublicFormat.UncompressedPoint)[1:]
#Copy these numbers into the arguments for the ATECC608 ECDH algorithm.
print("Server X component:", server_public_key_bytes[:32].hex().upper())
print("Server Y component:", server_public_key_bytes[32:].hex().upper())

shared_secret = server_private_key.exchange(ec.ECDH(),device_pub_key)
print("Calculated Shared Secret:", shared_secret.hex().upper())
#Copy output from ATECC608A here:
ecdh_calc = bytes.fromhex('D6 5F 53 A7 4C 07 90 53 09 23 3C 01 6A 69 25 7A BD B0 58 C5 82 D9 C3 F5 5B D4 31 3F B8 5E AA E9')
print(ecdh_calc == shared_secret)


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
cipher = Cipher(algorithms.AES(shared_secret[16:]), modes.ECB(), backend=default_backend())
encryptor = cipher.encryptor()
cipher_text = encryptor.update(b'\x0F'*16) + encryptor.finalize()
print("Cipher Text: ",cipher_text.hex().upper())
