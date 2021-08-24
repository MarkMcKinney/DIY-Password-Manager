import base64
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
import random
import getpass
import argon2
from argon2 import PasswordHasher

# OPERATION FUNCTIONS

def encrypt_data(input, hashed_pass):
    message = input.encode()
    f = Fernet(hashed_pass)
    encrypted = f.encrypt(message)
    return (encrypted)

def decrypt_data(input, hashed_pass):
    f = Fernet(hashed_pass)
    decrypted = f.decrypt(input)
    return (decrypted)

def argon2Hash(input):

    ph = PasswordHasher(time_cost=32, memory_cost=8589935000, parallelism=8, hash_len=256, salt_len=32, encoding='utf-8',
                        type=argon2.Type.ID)
    hash = ph.hash(input.encode())

    return hash

def vaultSetup():
    password_provided = getpass.getpass("What would you like your master password to be? ")
    password = password_provided.encode() # Convert to type bytes
    salt = os.urandom(32)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    hashed_entered_pass = base64.urlsafe_b64encode(kdf.derive(password)) # Can only use kdf once

    file = open("SALT.txt", "wb")
    file.write(salt)
    file.close()
    del salt

    file = open("VERIFIER.txt", "wb")
    file.write(encrypt_data("entered_master_correct",hashed_entered_pass))
    file.close()

    file = open("pm_db.mmf", "w+")
    file.write(str(encrypt_data("{}",hashed_entered_pass).decode('utf-8')))
    file.close()
    del hashed_entered_pass

    input("Your password vault was created. Access it using the pm_db.py file. Press ENTER to continue to login...")
