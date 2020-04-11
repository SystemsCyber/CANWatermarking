
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

key = bytes.fromhex('BD90DF57D14A593769F4B5207EC472BC')
print("Set Key for CMAC")
print(''.join(['0x{:02X},'.format(b) for b in key]))
msg = bytes.fromhex('6FAA398B3A858402A50B895EE617B91666011BC4EBCB52AB78E0BEFA2B96A0E6DDFB897E77AD628A12F250A478645900F8312CC0395B0AC9CDC3D359207F0754')
print("Initializing CMAC")
c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
print("Adding data for CMAC")
print(''.join(['0x{:02X},'.format(b) for b in msg]))
c.update(msg)
c.update(b'\x00'*64) #Padding was on the message
print("OMAC Copy Finalize 1:")
print(c.copy().finalize().hex().upper())
print("Add data again.")
c.update(msg + b'\x00'*64)
print("OMAC Copy Finalize 2:")
print(c.copy().finalize().hex().upper())
c.update(b'\x00')
print("OMAC Finalize:")
print(c.finalize().hex().upper())

'''
From https://tools.ietf.org/html/rfc4493.html
Test Vectors
   --------------------------------------------------
   Subkey Generation
   K              2b7e1516 28aed2a6 abf71588 09cf4f3c
   AES-128(key,0) 7df76b0c 1ab899b3 3e42f047 b91b546f
   K1             fbeed618 35713366 7c85e08f 7236a8de
   K2             f7ddac30 6ae266cc f90bc11e e46d513b
   --------------------------------------------------
   --------------------------------------------------
   Example 1: len = 0
   M              <empty string>
   AES-CMAC       bb1d6929 e9593728 7fa37d12 9b756746
   --------------------------------------------------
'''
print()
print("Test Vectors from RFC4493")
key = bytes.fromhex('2b7e1516 28aed2a6 abf71588 09cf4f3c')
print("Set Key for CMAC")
print(''.join(['0x{:02X},'.format(b) for b in key]))
print('Example 1')
print('AES-CMAC: bb1d6929e95937287fa37d129b756746')
c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
print('AES-CMAC:', c.finalize().hex().upper())

'''
   Example 2: len = 16
   M              6bc1bee2 2e409f96 e93d7e11 7393172a
   AES-CMAC       070a16b4 6b4d4144 f79bdd9d d04a287c
   --------------------------------------------------
'''
print('Example 2')
print('AES-CMAC: 070a16b46b4d4144f79bdd9dd04a287c')
c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
c.update(bytes.fromhex('6bc1bee2 2e409f96 e93d7e11 7393172a'))
print('AES-CMAC:', c.finalize().hex().upper())
'''
   Example 3: len = 40
   M              6bc1bee2 2e409f96 e93d7e11 7393172a
                  ae2d8a57 1e03ac9c 9eb76fac 45af8e51
                  30c81c46 a35ce411
   AES-CMAC       dfa66747 de9ae630 30ca3261 1497c827
   --------------------------------------------------
'''
print('Example 3')
print('AES-CMAC: dfa66747de9ae63030ca32611497c827')
c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
c.update(bytes.fromhex('6bc1bee2 2e409f96 e93d7e11 7393172a'+
                       'ae2d8a57 1e03ac9c 9eb76fac 45af8e51'+
                       '30c81c46 a35ce411'))
print('AES-CMAC:', c.finalize().hex().upper())

'''
   Example 4: len = 64
   M              6bc1bee2 2e409f96 e93d7e11 7393172a
                  ae2d8a57 1e03ac9c 9eb76fac 45af8e51
                  30c81c46 a35ce411 e5fbc119 1a0a52ef
                  f69f2445 df4f9b17 ad2b417b e66c3710
   AES-CMAC       51f0bebf 7e3b9d92 fc497417 79363cfe
   --------------------------------------------------
'''
print('Example 4')
print('AES-CMAC: 51f0bebf7e3b9d92fc49741779363cfe')
c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
data = bytes.fromhex('''6bc1bee2 2e409f96 e93d7e11 7393172a
                  		  ae2d8a57 1e03ac9c 9eb76fac 45af8e51
                          30c81c46 a35ce411 e5fbc119 1a0a52ef
                          f69f2445 df4f9b17 ad2b417b e66c3710''')
c.update(data)
print('AES-CMAC:', c.finalize().hex().upper())