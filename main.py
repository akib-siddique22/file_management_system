'''
Note:
pip install pycryptodome
pip install eciespy
'''
import time
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import PKCS1_OAEP
import os
import os.path
from getpass import getpass
from pathlib import Path
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt


class FileEncrypt:
    def __init__(self, key):
        self.key = key

    def encryptf(self, filename): #passphrase encryption
        with open(filename, 'rb')as f:
            fileContent = f.read()
        cipher = AES.new(self.key, AES.MODE_CBC) #using AES, CBC
        encryptContent = cipher.encrypt(pad(fileContent, AES.block_size))
        with open("cloud/"+filename + ".enc", 'wb') as f:
            f.write(cipher.iv)
            f.write(encryptContent)
        os.system('cls')
        print("Encryption Successful!\n")
    
    def decryptf(self, filename): #passphrase decryption
        with open("cloud/"+filename, 'rb') as f:
            iv = f.read(16)
            decryptContent = f.read()
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        decryptContent = unpad(cipher.decrypt(decryptContent), AES.block_size)
        with open(filename[:-4],'wb') as f:
            f.write(decryptContent)
        os.system('cls')
        print("Decryption Successful!\n")

def keyEncrypt(filename, keyName):

    with open(filename, 'rb')as f:
        fileContent = f.read()

    with open("cloud/" + keyName, "rb") as f:
        publicKey = f.read()

    encContent = encrypt(publicKey, fileContent)
    with open("cloud/"+filename + ".enc", 'wb') as f:
        f.write(encContent)
    os.system('cls') 
    print("Public Key Encryption Successful!\n")


def keyDecrypt(filename, keyName):
    with open("cloud/" + filename, 'rb')as f:
        fileContent = f.read()

    with open(keyName, "rb") as f:
        privateKey = f.read()

    decContent = decrypt(privateKey, fileContent)
    with open(filename[:-4],'wb') as f:
        f.write(decContent)
    os.system('cls')
    print("Private Key Decryption Successful!\n")
        
salt = b'\xeb\xd1\xc7G\xdc\xcc-R\xc5r\xecs*+b\xb8;s\xbf\x82\x91\xda\xb5\xe4\x0b\xd1\xa6}vq\xebD'

if(Path('cloud').is_dir() == False):
    os.makedirs('cloud')



while True:
    print("File Management System:\n1. Encrypt With Passphrase\n2. Decrypt with Passphrase\n3. Generate new Public and Private Key\n4. Encrypt with Public Key\n5. Decrypt with Private Key\n6. Create New File")
    userIn = input("Select your choice by typing the number (type \"exit\" to quit): ")
    print("\n")

    if userIn == "1":
        passphrase = getpass("\nNew Passphrase: ")
        print(passphrase) #testing delete later
        if((len(passphrase) < 5) or (any(str.isdigit(x) for x in passphrase) == False) ): #password requirements
            os.system('cls')
            print("Passphrase needs to contain a number and be at least 5 characters long\n")
            continue
        filename = input("File to Encrypt: ")
        path = Path(filename)
        if(path.is_file() == False): #check if file exists
            os.system('cls')
            print("File does not exist\n")
            continue
        
        key = PBKDF2(passphrase, salt, dkLen=32) #PBKF2 is a cryptographic key derivation function
        encr = FileEncrypt(key)
        encr.encryptf(filename)

    elif userIn == "2":
        passphrase = getpass("\nPassphrase: ") #hide password on the screen
        print(passphrase) #testing delete later
        filename = input("File to Decrypt (include \".enc\"): ")
        path = Path("cloud/"+filename)
        if(path.is_file() == False): #check if file exits
            os.system('cls')
            print("File does not exist\n")
            continue
        
        key = PBKDF2(passphrase, salt, dkLen=32) #PBKF2 is a cryptographic key derivation function
        encr = FileEncrypt(key)
        try:
            encr.decryptf(filename)
        except:
            os.system('cls')
            print("Failed to Decrypt. Incorrect Passphrase\n")


    elif userIn == "3":
        perm = input("Warning! Naming a key the same as an existing one will overwrite it, type \"okay\" to proceed: ")
        if(perm != "okay"):
            os.system('cls')
            print("You did not want to confirm the generation of keys\n")
            continue
        keys = generate_key()
        privateKey = keys.secret
        publicKey = keys.public_key.format(True)

        while True: #validation
            publicName = input("Name you public key with \".pem\": ")
            privateName = input("Name you private key with \".pem\": ")
            if (publicName != privateName) and (len(publicName) >= 4) and (len(privateName) >= 4) and (publicName[-4:] == ".pem") and (privateName[-4:] == ".pem"):
                break
            print("\nThe names need to contain \".pem\" in the end. Private Key and Public Key should be named differently\n")

        path = "cloud/" + publicName

        with open(path, "wb") as f:
            f.write(publicKey)

        with open(privateName, "wb") as f:
            f.write(privateKey)
        os.system('cls')
        print("You have successfully generated a key pair\n")

    elif userIn == "4":
        pubKeyName = input("Name you public key with \".pem\": ")

        path = Path('cloud/' + pubKeyName)
        if(path.is_file() == False):
            os.system('cls')
            print("You do not have that specific public key. Choose option 3 to create a key pair.\n")
            continue
        
        filename = input("File to Encrypt: ")
        path = Path(filename)
        if(path.is_file() == False): #check if file exists
            os.system('cls')
            print("File does not exist\n")
            continue
        keyEncrypt(filename, pubKeyName)

    elif userIn == "5":
        priKeyName = input("Name you private key with \".pem\": ")

        path = Path(priKeyName)
        if(path.is_file() == False): #check if that private key exists
            os.system('cls')
            print("You do not have that specific private key. Choose option 3 to create a key pair.\n")
            continue

        filename = input("File to Decrypt (include \".enc\"): ")
        pathFile = Path("cloud/"+filename)
        if(pathFile.is_file() == False): #check if file exists
            os.system('cls')
            print("File does not exist\n")
            continue

        try:
            keyDecrypt(filename, priKeyName)
        except:
            os.system('cls')
            print("Failed to Decrypt. Incorrect Private Key\n")


    elif userIn == "6":
        filename = input("Name the File: ")
        message = input("Message you want to write: ")
        with open(filename,'wt') as f:
            f.write(message)
        os.system('cls')
        print('Successfully Created File\n')

    elif userIn == "exit":
        print("/n Application Close. Have a Good Day!")
        break
time.sleep(2)
sys.exit()



