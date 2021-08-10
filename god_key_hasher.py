import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import random

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

password_provided = input("What would you like your master password to be? ")
password = password_provided.encode() # Convert to type bytes
salt = os.urandom(random.randint(16,256))
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
hashed_entered_pass = base64.urlsafe_b64encode(kdf.derive(password)) # Can only use kdf once

file = open("SALT.txt", "wb")
file.write(salt)
file.close()

file = open("VERIFIER.txt", "wb")
file.write(encrypt_data("entered_master_correct",hashed_entered_pass))
file.close()

file = open("pm_db.mmf", "w+")
file.write(str(encrypt_data("{}",hashed_entered_pass).decode('utf-8')))
file.close()

print("Your password vault was created. Access it using the pm_db.py file.")
