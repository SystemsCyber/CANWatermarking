# !/bin/env/python
from PyQt5.QtWidgets import (QMainWindow,
                             QWidget,
                             QMessageBox,
                             QFileDialog,
                             QLabel,
                             QLineEdit,
                             QVBoxLayout,
                             QApplication,
                             QTableView,
                             QTableWidgetItem,
                             QAbstractItemView,
                             QGridLayout,
                             QGroupBox,
                             QComboBox,
                             QAction,
                             QDialog,
                             QFrame,
                             QDialogButtonBox,
                             QInputDialog,
                             QProgressDialog,
                             QFormLayout,
                             QPlainTextEdit)
from PyQt5.QtCore import Qt, QTimer, QAbstractTableModel, QCoreApplication, QSize
from PyQt5.QtGui import QIcon

import requests
import threading
import queue
import datetime
import time
import base64
import sys
import struct
import json
import os
import traceback
import string
import random
import logging

import serial
import serial.tools.list_ports

import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


import jwkest
from jwkest.jwk import load_jwks_from_url, load_jwks
from jwkest.jws import JWS
jws = JWS()


logger = logging.getLogger()
logger.addHandler(logging.StreamHandler(sys.stdout))
logger.setLevel(logging.DEBUG)

AWS_REGION = "us-east-1"
API_ENDPOINT = r"https://jeg5qkwei4.execute-api.us-east-1.amazonaws.com/dev/"
APP_CLIENT_ID = "213ifn0mjhb64msjfp1bege1eb"
USER_POOL_ID = "us-east-1_hwjLE3kJY"
IDENTITY_TOKEN_NAME = "identity_token.json"
ACCESS_TOKEN_NAME = "access_token.json"

def decode_jwt(token):
    """
    Validate and decode the web token from the Amazon Cognito.
    Stores the public key needed to decrypt the token.
    Returns 
    """
    url="https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json".format(AWS_REGION,USER_POOL_ID)
    try:
        r = requests.get(url)
        logger.debug(r.status_code)
        key_set = load_jwks(r.text)
    except:
        logger.debug(traceback.format_exc())
        return False
    try:
        token_dict = jws.verify_compact(token, keys=key_set)
        logger.info(token_dict)
        if token_dict['exp'] < time.time():
            logger.debug("Token Expired")
            return False
        return {"user_id":token_dict['sub'], 
                "user_email":token_dict['email']}
        # if token_dict['email_verified']:
        #     return {"user_id":token_dict['sub'], 
        #             "user_email":token_dict['email']}
        # else:
        #     logger.debug("E-mail not verfied.")
        #     return False
    except:
        logger.debug(traceback.format_exc())
        return False

class SerialListener(threading.Thread):
    def __init__(self, rx_queue, serial_port):
        threading.Thread.__init__(self)
        self.rx_queue = rx_queue
        self.ser = serial_port
        self.ser.timeout = None
        self.runSignal = True
        logger.debug("Started Serial Listening Thread on {}".format(self.ser.port))

    def run(self):
        while self.runSignal:
            i = max(1, min(2048, self.ser.in_waiting))
            data = self.ser.read(i)
            self.rx_queue.put(data) 
        logger.debug("Serial Listener Thread is finished.")

class ProvisioningApp(QMainWindow):
    def __init__(self):
        super(ProvisioningApp, self).__init__()
        self.home_directory = os.getcwd()
        try:
            self.API_KEY = os.environ["CANWatermarking_API_KEY"]
        except:
            logger.critical(traceback.format_exc())
            QMessageBox.warning(self,"Missing API Key","Please contact Jeremy Daily at Colorado State University to obtain an API key for this application.")
            #sys.exit()
        self.statusBar().showMessage("Welcome to the CANWatermarking Provisioning App.")

         # Build common menu options
        menubar = self.menuBar()

        #####################
        # USER
        #####################
        user_menu = menubar.addMenu('&User')
        logger_menu = menubar.addMenu('&Device')
        server_menu = menubar.addMenu('&Server')
        util_menu = menubar.addMenu('U&tility')

        user_toolbar = self.addToolBar("User")
        logger_toolbar = self.addToolBar("Device")
        server_toolbar = self.addToolBar("Server")
        util_toolbar = self.addToolBar("Utility")
        
        login = QAction(QIcon(r'icons/new_icon.png'), '&Login', self)
        login.setShortcut('Ctrl+L')
        login.setStatusTip('User login.')
        login.triggered.connect(self.login)
        user_menu.addAction(login)
        user_toolbar.addAction(login)

        #####################
        # CONDITIONER
        #####################
        connect_conditioner = QAction(QIcon(r'icons/connect_icon.png'), 'Connect To &Device', self)
        connect_conditioner.setShortcut('Ctrl+D')
        connect_conditioner.setStatusTip('Connect to a device through USB.')
        connect_conditioner.triggered.connect(self.connect_conditioner_by_usb)
        logger_menu.addAction(connect_conditioner)
        logger_toolbar.addAction(connect_conditioner)

       

        get_key = QAction(QIcon(r'icons/get_key.png'), 'Get &Key/Decrypt File', self)
        get_key.setShortcut('Ctrl+K')
        get_key.setStatusTip('Get the plaintext session key and decrypt log file.')
        get_key.triggered.connect(self.get_session_key)
        logger_menu.addAction(get_key)
        logger_toolbar.addAction(get_key)

        get_key = QAction(QIcon(r'icons/get_key.png'), 'Get Server Public Key', self)
        get_key.setShortcut('Ctrl+P')
        get_key.setStatusTip('Get stored server public key')
        get_key.triggered.connect(self.get_server_public_key)
        logger_menu.addAction(get_key)
        logger_toolbar.addAction(get_key)

        #####################
        # Server
        #####################
       
       
        #####################
        # UTILITY
        #####################
        get_password = QAction(QIcon(r'icons/get_password.png'), 'Get &Password', self)
        get_password.setShortcut('Ctrl+P')
        get_password.setStatusTip('Decrypt the server private key password.')
        get_password.triggered.connect(self.decrypt_password)
        util_menu.addAction(get_password)
        util_toolbar.addAction(get_password)

        provision_logger = QAction(QIcon(r'icons/provision_icon.png'), '&Provision', self)
        provision_logger.setShortcut('Ctrl+V')
        provision_logger.setStatusTip('Register important data with the server.')
        provision_logger.triggered.connect(self.provision)
        util_menu.addAction(provision_logger)
        util_toolbar.addAction(provision_logger)

        self.setWindowTitle("CAN Logger Client Application")
        
        self.meta_data_dict       = None
        self.server_meta_data_dict= None
        self.access_token         = None
        self.identity_token       = None
        self.refresh_token        = None
        self.connected            = False
        self.encrypted_log_file   = None
        self.session_key          = None
        self.connection_type      = None
        self.list_file 			  = True

        self.character1 = ' '
        self.character2 = ','


        initial_message = QLabel("Connect to a CAN Logger (Ctrl+L) or to AWS server (Ctrl+S) to see files.")
        self.grid_layout = QGridLayout()
        self.grid_layout.addWidget(initial_message,0,0,1,1)
        main_widget = QWidget()
        main_widget.setLayout(self.grid_layout)
        self.setCentralWidget(main_widget)
        self.setWindowIcon(QIcon(r'icons/csu_icon.png'))

        self.show() 
        if not self.load_tokens():
            self.login()
    
    def get_server_public_key(self):
        while not self.connected:
            if self.connect_conditioner_by_usb() is None:
                return
        logger.debug("Sending LOCK Command")
        self.empty_serial()
        self.ser.write(b'LOCK\n')
        time.sleep(1)
        ret_val = self.get_serial_response()
        logger.debug("Returned Server Public Key:")
        logger.debug(ret_val)
        QMessageBox.information(self,"Stored Key","Returned Server Public Key:\n{}".format(ret_val))
           

    def provision(self):
        buttonReply = QMessageBox.question(self,"Provision Process","Are you performing provisioning and does your device has the provisioning firmware?",QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if buttonReply != QMessageBox.Yes:
            return
        if not decode_jwt(self.identity_token):
            message = "A valid webtoken is not available to get data. Please login."
            logger.warning(message)
            QMessageBox.warning(self,"Invalid Token",message)
            return
        while not self.connected:
            if self.connect_conditioner_by_usb() is None:
                return
        self.empty_serial()
        self.ser.write(b'KEY\n')
        response=self.get_serial_response().split(b'\n')
        logger.debug(response)
        try:
            serial_number = response[0]
            device_public_key = response[1]
        except IndexError:
            logger.debug("Not able to get serial number or response.")
            return
        
        try:
            data = {'serial_number': base64.b64encode(serial_number).decode("ascii"),
                    'device_public_key': base64.b64encode(device_public_key).decode("ascii"),
                   }
        except TypeError:
            logger.warning("Must have data to get key.")
            return

        url = API_ENDPOINT + "provision"
        header = {}
        header["x-api-key"] = self.API_KEY #without this header, the API Gateway will return a 403: Forbidden message.
        header["Authorization"] = self.identity_token #without this header, the API Gateway will return a 401: Unauthorized message
        try:
            r = requests.post(url, json=data, headers=header)
        except requests.exceptions.ConnectionError:
            QMessageBox.warning(self,"Connection Error","The there was a connection error when connecting to\n{}\nPlease try again once connection is established".format(url))
            return
        print(r.status_code)
        print(r.text)
        if r.status_code == 200: #This is normal return value
            try:
                data_dict = r.json()
                device_id = data_dict['id']
                rsa_public_key = base64.b64decode(data_dict['rsa_public_key'])
                assert len(rsa_public_key) == 270
                rsa_public_key_signature = base64.b64decode(data_dict['rsa_public_key_signature'])
                server_public_key = base64.b64decode(data_dict['server_public_key'])
                device_password = base64.b64decode(data_dict['device_password'])
                device_code = base64.b64decode(data_dict['device_code'])
                device_public_key_hash = data_dict['device_public_key_prov_hash']
                server_public_key_hash = data_dict['server_public_key_prov_hash']
                

                self.serial_id = serial_number.decode('utf-8')
                logger.debug("Device ID from Server: {}".format(device_id))
                logger.debug("Device ID from Serial: {}".format(device_id))
                assert device_id == self.serial_id

                # server_public_key=base64.b64decode(data_dict["server_public_key"]).hex().upper()
                # server_pem_key_pass=base64.b64decode(data_dict["server_pem_key_pass"]).decode('ascii')
                # encrypted_rand_pass=data_dict["encrypted_rand_pass"] #base64 format in string type
                # self.server_pem = server_pem_key_pass
                # self.rand_pass = encrypted_rand_pass
                assert len(server_public_key)==64
                
                # Visual key hash confirmation before sending the server public key to the device
                device_pub_key_bytes = bytes(bytearray.fromhex(device_public_key.decode('utf-8')))
                device_public_key_hash = hashlib.sha256(device_pub_key_bytes).digest().hex().upper()
                logger.debug("Device Public Key Hash From Server: {}".format(data_dict['device_public_key_prov_hash']))
                logger.debug("Device Public Key Hash From Serial: {}".format(device_public_key_hash))
                assert data_dict['device_public_key_prov_hash'] == device_public_key_hash
                
                server_public_key_hash = hashlib.sha256(server_public_key).digest().hex().upper()
                logger.debug("Server Public Key Hash From Server: {}".format(data_dict['server_public_key_prov_hash']))
                logger.debug("Server Public Key Hash From Serial: {}".format(server_public_key_hash))
                assert data_dict['server_public_key_prov_hash'] == server_public_key_hash
                
                
                logger.debug("Writing Server Public Key to Serial")
                logger.debug(server_public_key.hex().upper())
                time.sleep(0.1)
                self.ser.write(b'ECC\n')
                time.sleep(0.1)
                self.ser.write(server_public_key)
                time.sleep(1)
                logger.debug("YELLOW LED should be lit.") 
                time.sleep(0.1)
                self.ser.write(b'RSA\n')
                time.sleep(0.1)
                self.ser.write(rsa_public_key)
                time.sleep(1)
                logger.debug("RED LED should be lit.") 

                logger.debug("Sending LOCK Command")
                self.ser.write(b'LOCK\n')
                ret_val = self.get_serial_response()
                logger.debug("Returned Server Public Key:")
                logger.debug(ret_val.decode('ascii'))
                logger.debug(server_public_key.hex().upper())
                logger.debug("The above two lines should match.\nGREEN LED should be lit.") 
                assert ret_val.decode('ascii') == server_public_key.hex().upper()

                logger.debug("Requesting Stored RSA Key.")
                time.sleep(0.1)
                self.ser.write(b'GETRSA\n')
                ret_val = self.get_serial_response()
                logger.debug("Returned RSA Key:")
                logger.debug(ret_val.decode('ascii'))
                logger.debug(rsa_public_key.hex().upper())
                logger.debug("The above two lines should match.") 
                assert ret_val.decode('ascii') == rsa_public_key

                QMessageBox.information(self,"Provisioning Process",
                        "Server Public Key has been stored and locked in device {}".format(self.serial_id))
                #self.ask_to_save()
            except:
                msg = traceback.format_exc()
                logger.debug(msg)
                QMessageBox.warning(self,"Error",msg)
        
        else:
            QMessageBox.warning(self,"Error",r.text)

    #Ask the operator if they want to save the server_pem_key and encrypted_rand_pass
    def ask_to_save(self):
        buttonReply = QMessageBox.question(self, 'Save File', "Would you like to save the server private key and its encrypted password?", QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if buttonReply == QMessageBox.Yes:
            self.save_security_list()


    def save_security_list(self):
        #Save the server pem key with pass and encrypted password to a text file
        self.server_pem = server_public_key
        options = QFileDialog.Options()
        options |= QFileDialog.Detail
        self.data_file_name, data_file_type = QFileDialog.getSaveFileName(self,
                                            "Save File",
                                            self.home_directory + "/" + "CAN Conditioner Security List",
                                            "JSON Files (*.json);;All Files (*)",
                                            options = options)
        if self.data_file_name:
            if os.path.exists(self.data_file_name) == True:
            #if os.path.getsize(self.data_file_name) >0:
                with open(self.data_file_name,'r') as file:
                    data = json.load(file)
                data[self.serial_id] = {'server_pem_key':self.server_pem,'encrypted_password':self.rand_pass}
                with open(self.data_file_name,'w') as file:
                    json.dump(data,file, indent=4)
                
            else:
                with open(self.data_file_name,'w') as file:
                    data = {self.serial_id:{'server_pem_key':self.server_pem,'encrypted_password':self.rand_pass}}
                    json.dump(data,file, indent=4)
            QMessageBox.information(self,"Save File","File is successfully saved!")
                
    def decrypt_password(self):
        text_bytes, okPressed = QInputDialog.getText(self, "Data Entry","Bytes to encrypt in hex:", QLineEdit.Normal)
        cipher_bytes = self.encrypt_block(bytes.fromhex(text_bytes))
        QMessageBox.information(self,'Cipher Text',"Plain Text: {}\nCipher Text: {}\n".format(text_bytes,cipher_bytes.hex()))

    def encrypt_block(self, plain_bytes):
        # Send the encrypted server pem key password to the device for encryption
        #Must be done after the provisioning process
        
        #Open serial COM port if not connected
        while not self.connected:
            if self.connect_conditioner_by_usb() is None:
                return
        padded_plain_bytes = b'\x00'*(16-len(plain_bytes[:16])) + plain_bytes
        logger.debug("Encrypting the following bytes:\n{}".format(padded_plain_bytes))
        assert len(padded_plain_bytes) == 16
        # empty the queue
        self.empty_serial()
        self.ser.write(b'PASSWORD\n')
        time.sleep(0.1)
        self.ser.write(padded_plain_bytes)
        encrypted_bytes = bytes.fromhex(self.get_serial_response().decode('ascii'))
        logger.debug("encrypted_bytes = {}".format(encrypted_bytes))
        return encrypted_bytes

    def get_serial_response(self):
        time.sleep(1)
        ret_val = b''
        while not self.serial_queue.empty():
            try:
                character = self.serial_queue.get(timeout=1)
                ret_val += character
            except queue.Empty:
                logger.debug("No Response from Device. Is it provisioned?")
                return
        return ret_val

    def empty_serial(self):
        while not self.serial_queue.empty():
            self.serial_queue.get_nowait()
        time.sleep(0.1)

    def get_session_key(self):
        if not decode_jwt(self.identity_token):
            message = "A valid webtoken is not available to get data. Please login."
            logger.warning(message)
            QMessageBox.warning(self,"Invalid Token",message)
            return
        
        while not self.connected:
            if self.connect_conditioner_by_usb() is None:
                return
        self.empty_serial()
        self.ser.write(b'SERIAL\n')
        self.device_serial_number = self.get_serial_response().decode('ascii').strip()
        logger.debug("self.device_serial_number = {}".format(self.device_serial_number))
        logger.debug(len(self.device_serial_number))
        data = {'serial_number': self.device_serial_number}
        url = API_ENDPOINT + "get_key"
        header = {}
        header["x-api-key"] = self.API_KEY #without this header, the API Gateway will return a 403: Forbidden message.
        header["Authorization"] = self.identity_token #without this header, the API Gateway will return a 401: Unauthorized message
        try:
            r = requests.post(url, json=data, headers=header)
        except requests.exceptions.ConnectionError:
            QMessageBox.warning(self,"Connection Error","The there was a connection error when connecting to\n{}\nPlease try again once connection is established".format(url))
            return
        print(r.status_code)
        print(r.text)
        if r.status_code == 200: #This is normal return value
            key_dict = r.json()
            msg = ''
            for k,v in key_dict.items():
                msg += "{} = {}\n\n".format(k,v)
            print("key_dict = {}".format(key_dict))
            QMessageBox.information(self,"Keys","{}".format(msg))
            serial_number =  key_dict['id']
            #convert to bytes
            device_code = key_dict['device_code'].encode('ascii')
            device_password = key_dict['device_password'].encode('ascii')
            server_encrypted_pem = key_dict['server_private_key'].encode('ascii')
            self.decrypt_server_key(serial_number, server_encrypted_pem, device_code, device_password)
            
        else:
            QMessageBox.information(self,"Error","The server returned a status code {}.\n{}".format(r.status_code,r.content))  

    def decrypt_server_key(self, serial_number, server_encrypted_pem, device_code, device_password):
        if not self.connected:
            QMessageBox.warning(self, "Connected","You must be connected to decrypt the server key.")
            return

        full_password = device_password + self.encrypt_block(device_code)
        server_private_key = serialization.load_pem_private_key(server_encrypted_pem, 
                                                            password=full_password, 
                                                            backend=default_backend())
        print("Old Device full_password = ", full_password)
        choices = string.ascii_letters + string.digits
        new_device_password = ''.join(random.choices(choices,k=8))
        password = ''
        while len(password) != 8:
            password, okPressed = QInputDialog.getText(self, "Password","Input exactly 8 characters for new password for \n{}".format(serial_number), QLineEdit.Normal, new_device_password)
        
        new_full_password = password.encode('ascii') + full_password[8:24]
        assert len(new_full_password) == 24
        print("New Device full_password = ", new_full_password)

        #Serialize server private key with password from full_password
        new_server_pem_key_pass = server_private_key.private_bytes(
                                encoding = serialization.Encoding.PEM,
                                format = serialization.PrivateFormat.PKCS8,
                                encryption_algorithm = serialization.BestAvailableEncryption(new_full_password))
        
        pem_filename, data_file_type = QFileDialog.getSaveFileName(self,
                                            "Save File",serial_number+'.pem', 
                                            "PEM Files (*.pem);;All Files (*)"
                                            )
        if pem_filename is not None:
            with open(pem_filename, 'wb') as pem_file:
                pem_file.write(new_server_pem_key_pass)
            # Do this only for provisioning to generate a backup.
            with open(pem_filename+'_password', 'wb') as pass_file:
                pass_file.write(new_full_password)

    def connect_conditioner_by_usb(self):
        self.connection_type = 'USB'

        items =[] 
        for device in serial.tools.list_ports.comports():
            items.append("{} - {}".format(device.device, device.description))
        logger.debug(items)
        com_port, okPressed = QInputDialog.getItem(self, "Select COM Port","CAN Logger USB Serial Port:", items, 0, False)
        if okPressed and com_port:
            logger.debug("Selected: {}".format(com_port))
            self.comport = com_port.split('-')[0].strip()
        else:
            return
        logger.debug("Trying to connect USB serial.")
        try:
            self.ser.close()
            del self.ser
        except AttributeError:
            pass

        try:
            self.ser = serial.Serial(self.comport)
            self.ser.set_buffer_size(rx_size = 2147483647, tx_size = 2000)
            self.connected = True
            logger.debug("Connected to Serial Port.")
            self.serial_queue = queue.Queue()
            self.serial_thread = SerialListener(self.serial_queue,self.ser)
            self.serial_thread.setDaemon(True) #needed to close the thread when the application closes.
            self.serial_thread.start()
            logger.debug("Started Serial Thread.")

            return True
        except serial.serialutil.SerialException:
            logger.debug(traceback.format_exc())
            self.connected = False
            if "PermissionError" in repr(traceback.format_exc()):
                QMessageBox.information(self,"USB Status","The port {} is already in use. Please unplug and replug the unit.".format(self.comport))
            else:
                self.connected = False
                return False

    def login(self):
        """
        Get a password from the user with a dialog box and submit it.
        Returns a token for further user authentication.
        """
        try:
            with open('username.txt','r') as f:
                stored_user = f.read()
            username_saved = True
        except:
            stored_user = ''
            username_saved = False
        self.user, okPressed = QInputDialog.getText(self, "Username","Username (e-mail):", QLineEdit.Normal, stored_user)
        
        # validate input
        if not okPressed:
            return
        if self.user == '':
            return
        
        if stored_user == self.user:
            username_saved == True
        else:
            username_saved == False

        try:
            with open('password.txt','r') as f:
                stored_password = f.read()
            password_saved = True
        except:
            stored_password = ''
            password_saved = False
        password, okPressed = QInputDialog.getText(self, "Password","Input password for \n{}".format(self.user), QLineEdit.Password, stored_password)
        
        # Validate Input
        if not okPressed:
            return
        if password == '':
            return
        
        if stored_password == password:
            password_saved == True
        else:
            password_saved == False

        #https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp.html#CognitoIdentityProvider.Client.initiate_auth
        post_data={
            "AuthParameters" : {
                "USERNAME" : self.user,
                "PASSWORD" : password
               },
               "AuthFlow" : "USER_PASSWORD_AUTH",
               "ClientId" : APP_CLIENT_ID
            }
        url = "https://cognito-idp.us-east-1.amazonaws.com"
        header = {}
        header["Content-Type"]= "application/x-amz-json-1.1"
        header["X-Amz-Target"]= "AWSCognitoIdentityProviderService.InitiateAuth"
        try:
            r = requests.post(url, json=post_data, headers=header)
        except requests.exceptions.ConnectionError:
            QMessageBox.warning(self,"Connection Error","The there was a connection error when connecting to\n{}\nPlease try again once connection is established".format(url))
            return
        logger.debug(r.status_code)
        if r.status_code == 200: #This is normal return value
            response_data = r.json()
            # for k,v in response_data["AuthenticationResult"].items():
            #     logger.debug("{}: {}".format(k,v))
            self.access_token = response_data["AuthenticationResult"]["AccessToken"]
            with open(ACCESS_TOKEN_NAME,'w') as fp:
                json.dump(self.access_token,fp)
            self.identity_token = response_data["AuthenticationResult"]["IdToken"]
            with open(IDENTITY_TOKEN_NAME,'w') as fp:
                json.dump(self.identity_token,fp)
            self.refresh_token = response_data["AuthenticationResult"]["RefreshToken"]
            self.load_tokens()

            if not (password_saved and username_saved):
                _password, okPressed = QInputDialog.getText(self, "Save Password","DANGER: Do you want to save your clear text username and password for \n{}? Press OK to save.".format(self.user), QLineEdit.Password, password)
                if okPressed:
                    with open('password.txt','w') as f:
                        f.write(password)
                    with open('username.txt','w') as f:
                        f.write(self.user) 
        elif r.status_code == 400: #Incorrect username or password
            message = r.json()["message"]
            logger.warning(message)
            QMessageBox.warning(self,"Incorrect Username or Password",message)
            self.login()
        else: #Something went wrong
            logger.warning("There was an issue with the web response.")
            logger.debug(r.text)
            

    def load_tokens(self):
        try:
            with open(IDENTITY_TOKEN_NAME,'r') as fp:
                self.identity_token = json.load(fp)
            with open(ACCESS_TOKEN_NAME,'r') as fp2:
                self.access_token = json.load(fp2)
            user_token = decode_jwt(self.identity_token)
            for k,v in user_token.items():
                logger.debug("{}: {}".format(k,v))
            return 
        except:
            logger.debug(traceback.format_exc())
            self.access_token = None
            self.identity_token = None
            return False

if __name__.endswith('__main__'):
    app = QApplication(sys.argv)
    execute = ProvisioningApp()
    sys.exit(app.exec_())
    

