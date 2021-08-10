import json
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import hashlib

# STORE CRYPTOGRAPHY VARIABLES

with open("SALT.txt", 'rb') as readfile:
    content = readfile.read()
    readfile.close()
cSALT = content

with open("VERIFIER.txt", 'rb') as readfile:
    content = readfile.read()
    readfile.close()
cVERIFIER = content

# TERMINAL FORMATTING
divider = "---------------------------------------------------------------------------------------------------------------------------\n"

# CRYPTOGRAPHY FUNCTIONS

def encrypt_data(input, hashed_pass):
    message = input.encode()
    f = Fernet(hashed_pass)
    encrypted = f.encrypt(message)
    return (encrypted)

def decrypt_data(input, hashed_pass):
    f = Fernet(hashed_pass)
    decrypted = f.decrypt(input)
    return (decrypted)

def verify_password(password_provided):
    verifier = cVERIFIER
    # Hash password for later comparison
    password = password_provided.encode() # Convert to type bytes
    salt = cSALT
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    hashed_entered_pass = base64.urlsafe_b64encode(kdf.derive(password)) # Can only use kdf once

    try:
        pass_verifier = decrypt_data(verifier,hashed_entered_pass)
        if pass_verifier == b'entered_master_correct':
            return (hashed_entered_pass)
    except:
        return (False)

file_path = "pm_db.mmf"
file = open(file_path, "rb")
contents = file.read()
file.close()

#PROFILE OPERATIONS

#Add new domain profile
def create_domain_file():
    add_domain = input("Website domain name: ")
    add_user = input("Username: ")
    add_password = input("Password: ")

    db[add_domain] = {"username":str(encrypt_data(add_user,hashed_pass).decode('utf-8')),"password":str(encrypt_data(add_password,hashed_pass).decode('utf-8'))}

    overwrite_db(encrypt_data(json.dumps(db),hashed_pass).decode('utf-8'))

    return ("Created "+add_domain+" profile successfully!")

def overwrite_db(new_contents):
    file = open(file_path, "w+")
    file.write(new_contents)
    file.close()

#RUN PROGRAM
# RUN LOGIN
print('''                               
                                   
                                                           ^jEQBQDj^             
                                                        r#@@@@@@@@@#r           
                                                        ?@@@#x_`_v#@@@x          
                                                        g@@@!     !@@@Q          
                                                        Q@@@_     _@@@B          
                                                    rgg@@@@QgggggQ@@@@ggr       
                                                    Y@@@@@@@@@@@@@@@@@@@Y       
                                                    Y@@@@@@@Qx^xQ@@@@@@@Y       
                                                    Y@@@@@@@^   ~@@@@@@@Y       
                                                    Y@@@@@@@@r r#@@@@@@@Y       
                                                    Y@@@@@@@@c,c@@@@@@@@Y       
                                                    Y@@@@@@@@@@@@@@@@@@@Y       
                                                    v###################v       
                                                   
                                                                
    ''')
# Require password to be entered
entered_pass = input("Enter Master Key: ")
#entered_pass = "innovativeMoose"
hashed_pass = verify_password(entered_pass)
db = json.loads(decrypt_data(contents,hashed_pass).decode('utf-8'))
print('''                               
                                   
                                                                       `xx.  
                                                                     'k#@@@h`
                                                                   _m@@@@@@Q,
                                                                 "M@@@@@@$*  
                                                 `xk<          =N@@@@@@9=    
                                                T#@@@Qr      ^g@@@@@@5,      
                                                y@@@@@@Bv  ?Q@@@@@@s-        
                                                `V#@@@@@#B@@@@@@w'          
                                                    `}#@@@@@@@@#T`            
                                                      vB@@@@Bx               
                                                        )ER)                            
                                                                                                       
    ''')
print (divider)

if hashed_pass != False:
    while True:

        user_cmd = input("\na = add profile | f = find profile data  | e = edit profile data | v = read all profiles | d = delete profile data\nWhat would you like to do? ")
        print("\n")
        # ADD PROFILE
        if user_cmd == "a":
            print (divider)
            print("ADD A PROFILE\n")
            create_domain_file()

        # READ PROFILE
        if user_cmd == "f":
            print (divider)
            print("FIND A PROFILE\n")
            read_domain = input("What is the domain you are looking for? ")
            try:
                domain_info = db[read_domain]
                username = str(decrypt_data(bytes(domain_info['username'], encoding='utf-8'),hashed_pass).decode('utf-8'))
                password = str(decrypt_data(bytes(domain_info['password'], encoding='utf-8'),hashed_pass).decode('utf-8'))
                print ("Username: "+username)
                print ("Password: "+password)
            except:
                print ("Could not find that domain saved")

        # READ ALL PROFILES
        if user_cmd == "v":
            print (divider)
            print("VIEWING ALL PROFILES\n")
            try:
                i = 0
                for e in db:
                    username = str(decrypt_data(bytes(db[e]['username'], encoding='utf-8'),hashed_pass).decode('utf-8'))
                    password = str(decrypt_data(bytes(db[e]['password'], encoding='utf-8'),hashed_pass).decode('utf-8'))
                    print (e)
                    print ("Username: "+username)
                    print ("Password: "+password)
                    print (divider)
                    i = i + 1
                if i == 0:
                    print ("No saved profiles")
            except:
                print ("Could not load all profiles")

        # EDIT PROFILE
        if user_cmd == "e":
            print (divider)
            print("EDIT A PROFILE\n")
            edit_domain = input("Website domain name: ")
            try:
                domain_info = db[edit_domain]
                curr_user = str(decrypt_data(bytes(domain_info['username'], encoding='utf-8'),hashed_pass).decode('utf-8'))
                curr_password = str(decrypt_data(bytes(domain_info['password'], encoding='utf-8'),hashed_pass).decode('utf-8'))
                edit_user = input("New Username (current: "+curr_user+"): ")
                if edit_user == "" or edit_user == " ":
                    edit_user = curr_user
                edit_password = input("New Password (current: "+curr_password+"): ")
                if edit_password == "" or edit_password == " ":
                    edit_password = curr_password
                db[edit_domain] = {"username":str(encrypt_data(edit_user,hashed_pass).decode('utf-8')),"password":str(encrypt_data(edit_password,hashed_pass).decode('utf-8'))}
                overwrite_db(encrypt_data(json.dumps(db),hashed_pass).decode('utf-8'))
                print ("Updated "+edit_domain+" profile successfully!")
            except:
                print ("This domain does not exist, changing to adding to new profile")
                create_domain_file()

        # DELETE PROFILE
        if user_cmd == "d":
            print (divider)
            print("DELETE A PROFILE\n")
            del_domain = input("Website domain name (type [c] if you want to cancel): ")
            if del_domain != "[c]":
                try:
                    del db[del_domain]
                    overwrite_db(encrypt_data(json.dumps(db),hashed_pass).decode('utf-8'))
                    print ("Deleted "+del_domain+" profile successfully!")
                except:
                    print ("Unable to find "+del_domain)


if hashed_pass == False:
    print ("Incorrect master passsword.")
