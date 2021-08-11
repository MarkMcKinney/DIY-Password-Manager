import json
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import getpass
import os
import threading, msvcrt
import sys
import difflib
import string
import secrets

# TERMINAL FORMATTING
divider = "-----------------------------------------------------------------------------------------------------------------------\n"
lockImg = '''                               
                                   
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
                                                   
                                                                
    '''
checkImg = '''                               
                                   
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
                                                                                                       
    '''
def displayHeader(title):
    os.system('cls' if os.name == 'nt' else 'clear')
    print(checkImg)
    print(divider)
    print(str(title) + "\n")


# STORE CRYPTOGRAPHY VARIABLES

with open("SALT.txt", 'rb') as readfile:
    content = readfile.read()
    readfile.close()
cSALT = content

with open("VERIFIER.txt", 'rb') as readfile:
    content = readfile.read()
    readfile.close()
cVERIFIER = content

# TIMEOUT
def timeoutCleanup():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(lockImg)
    print("\n\nYour session expired. For your security, the program has automatically exited. All submitted data is still saved.")

def timeoutInput(caption, default, timeout = 90):
    class KeyboardThread(threading.Thread):
        def run(self):
            self.timedout = False
            self.input = ''
            while True:
                if msvcrt.kbhit():
                    chr = msvcrt.getche()
                    if ord(chr) == 13:
                        break
                    elif ord(chr) >= 32:
                        self.input += str(chr.decode('UTF-8'))
                if len(self.input) == 0 and self.timedout:
                    break    
    result = default
    it = KeyboardThread()
    it.start()
    it.join(timeout)
    it.timedout = True
    if len(it.input) > 0:
        # wait for rest of input
        it.join()
        result = it.input
    print('')  # needed to move to next line
    return result

# CRYPTOGRAPHY FUNCTIONS

# Generate random password - user cannot request passwords that are less than 6 characters
# use secrets instead of random (secrets is safer)
def generate_password(length=12):
    if length < 6:
        length = 12
    uppercase_loc = secrets.choice(string.digits)  # random location of lowercase
    symbol_loc = secrets.choice(string.digits)  # random location of symbols
    lowercase_loc = secrets.choice(string.digits)  # random location of uppercase
    password = ''
    pool = string.ascii_letters + string.punctuation  # the selection of characters used
    for i in range(length):
        if i == uppercase_loc:   # this is to ensure there is at least one uppercase
            password += secrets.choice(string.ascii_uppercase)
        elif i == lowercase_loc:  # this is to ensure there is at least one uppercase
            password += secrets.choice(string.ascii_lowercase)
        elif i == symbol_loc:  # this is to ensure there is at least one symbol
            password += secrets.choice(string.punctuation)
        else:  # adds a random character from pool
            password += secrets.choice(pool)
    return password

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

def overwrite_db(new_contents):
    file = open(file_path, "w+")
    file.write(new_contents)
    file.close()

#RUN PROGRAM
# RUN LOGIN
print(lockImg)
# Require password to be entered
entered_pass = getpass.getpass("Enter Master Key: ")
hashed_pass = verify_password(entered_pass)

if hashed_pass != False:
    os.system('cls' if os.name == 'nt' else 'clear')
    db = json.loads(decrypt_data(contents,hashed_pass).decode('utf-8'))

    while True:

        print(checkImg)
        print (divider)
        user_cmd = print("\n(a)dd profile | (f)ind profile data  | (e)dit profile data | (r)ead all profiles | (d)elete profile data\n(g)enerate password | e(x)it\n\nWhat would you like to do? ")
        user_cmd = timeoutInput('', '*TIMEOUT*') 
        print("\n")
        # ADD PROFILE
        if user_cmd == "a":
            displayHeader("ADD A PROFILE")
            print("Website domain name:")
            add_domain = timeoutInput("","*TIMEOUT*")
            if add_domain == "*TIMEOUT*":
                timeoutCleanup()
                break
            print("Username:")
            add_user = timeoutInput("","*TIMEOUT*")
            if add_user == "*TIMEOUT*":
                timeoutCleanup()
                break
            print("Password:")
            add_password = timeoutInput("","*TIMEOUT*")
            if add_password == "*TIMEOUT*":
                timeoutCleanup()
                break

            db[add_domain] = {"username":str(encrypt_data(add_user,hashed_pass).decode('utf-8')),"password":str(encrypt_data(add_password,hashed_pass).decode('utf-8'))}
            overwrite_db(encrypt_data(json.dumps(db),hashed_pass).decode('utf-8'))
            print("Created "+add_domain+" profile successfully!")
            print("\nType and submit (m) to return to menu...")
            userContinue = timeoutInput("","*TIMEOUT*")
            if userContinue == "*TIMEOUT*":
                timeoutCleanup()
                break

        # READ PROFILE
        if user_cmd == "f":
            displayHeader("FIND A PROFILE")
            print("What's the domain you're looking for?")
            read_domain = timeoutInput("","*TIMEOUT*")
            if read_domain == "*TIMEOUT*":
                timeoutCleanup()
                break
            if read_domain != "c":              
                try:
                    domains = list(db.keys())
                    matches = difflib.get_close_matches(read_domain, domains)
                    if matches:
                        print("\nClosest match:\n")
                        for d in matches:
                            domain_info = db[d]
                            username = str(decrypt_data(bytes(domain_info['username'], encoding='utf-8'),hashed_pass).decode('utf-8'))
                            password = str(decrypt_data(bytes(domain_info['password'], encoding='utf-8'),hashed_pass).decode('utf-8'))
                            print(d)
                            print("Username: "+username)
                            print("Password: "+password+"\n")
                    else:
                        print("Could not find a match. Try viewing all saved profiles.")
                except:
                    print("Error finding profile.")
                print("\nType and submit (m) to return to menu...")
                userContinue = timeoutInput("","*TIMEOUT*")
            if userContinue == "*TIMEOUT*":
                timeoutCleanup()
                break

        # READ ALL PROFILES
        if user_cmd == "r":
            displayHeader("READING ALL PROFILES")
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
            print("\nType and submit (m) to return to menu...")
            userContinue = timeoutInput("","*TIMEOUT*")
            if userContinue == "*TIMEOUT*":
                timeoutCleanup()
                break

        # EDIT PROFILE
        if user_cmd == "e":
            displayHeader("EDIT A PROFILE")
            print("Website domain name (submit (c) to cancel): ")
            edit_domain = timeoutInput("","*TIMEOUT*")
            if edit_domain == "*TIMEOUT*":
                timeoutCleanup()
                break
            if edit_domain != "c":
                try:
                    domain_info = db[edit_domain]
                    curr_user = str(decrypt_data(bytes(domain_info['username'], encoding='utf-8'),hashed_pass).decode('utf-8'))
                    curr_password = str(decrypt_data(bytes(domain_info['password'], encoding='utf-8'),hashed_pass).decode('utf-8'))

                    print("New Username (submit (c) to keep the current: "+curr_user+"):")
                    edit_user = timeoutInput("","*TIMEOUT*")
                    if edit_user == "*TIMEOUT*":
                        timeoutCleanup()
                        break
                    if edit_user == "c":
                        edit_user = ""
                    if edit_user == "" or edit_user == " ":
                        edit_user = curr_user
                    
                    print("New Password (submit (c) to keep the current: "+curr_password+"):")
                    edit_password = timeoutInput("","*TIMEOUT*")
                    if edit_password == "*TIMEOUT*":
                        timeoutCleanup()
                        break
                    if edit_password == "c":
                        edit_password = ""
                    if edit_password == "" or edit_password == " ":
                        edit_password = curr_password

                    db[edit_domain] = {"username":str(encrypt_data(edit_user,hashed_pass).decode('utf-8')),"password":str(encrypt_data(edit_password,hashed_pass).decode('utf-8'))}
                    overwrite_db(encrypt_data(json.dumps(db),hashed_pass).decode('utf-8'))
                    print ("Updated "+edit_domain+" profile successfully!")
                    print("\nType and submit (m) to return to menu...")
                    userContinue = timeoutInput("","*TIMEOUT*")
                    if userContinue == "*TIMEOUT*":
                        timeoutCleanup()
                        break
                except:
                    print ("This domain does not exist, changing to adding to new profile")
                    print("\nType and submit (m) to return to menu...")
                    userContinue = timeoutInput("","*TIMEOUT*")
                    if userContinue == "*TIMEOUT*":
                        timeoutCleanup()
                        break

        # DELETE PROFILE
        if user_cmd == "d":
            displayHeader("DELETE A PROFILE")
            print("Write the exact saved domain name (type (c) to cancel): ")
            del_domain = timeoutInput("","*TIMEOUT*")
            if del_domain == "*TIMEOUT*":
                timeoutCleanup()
                break
            if del_domain != "c":
                try:
                    del db[del_domain]
                    overwrite_db(encrypt_data(json.dumps(db),hashed_pass).decode('utf-8'))
                    print ("Deleted "+del_domain+" profile successfully!")
                    print("\nType and submit (m) to return to menu...")
                    userContinue = timeoutInput("","*TIMEOUT*")
                    if userContinue == "*TIMEOUT*":
                        timeoutCleanup()
                        break
                except:
                    print ("Unable to find "+del_domain)
                    print("\nType and submit (m) to return to menu...")
                    userContinue = timeoutInput("","*TIMEOUT*")
                    if userContinue == "*TIMEOUT*":
                        timeoutCleanup()
                        break

        # GENERATE PASSWORD
        if user_cmd == "g":
            displayHeader("GENERATE RANDOM PASSWORD")
            print("How long would like your password (type (c) to cancel): ")
            pass_length = str(timeoutInput("","*TIMEOUT*"))
            if pass_length == "*TIMEOUT*":
                timeoutCleanup()
                break
            if pass_length != "c":
                try:
                    if int(pass_length) < 6:
                        pass_length = str(12)
                        print("\nPasswords must be at least 6 characters long.")            
                    print("\nYour "+pass_length+" Character Password: "+generate_password(int(pass_length)))
                    print("\nType and submit (m) to return to menu...")
                    userContinue = timeoutInput("","*TIMEOUT*")
                    if userContinue == "*TIMEOUT*":
                        timeoutCleanup()
                        break
                except:
                    print("Unable to generate password.")
                    print("\nType and submit (m) to return to menu...")
                    userContinue = timeoutInput("","*TIMEOUT*")
                    if userContinue == "*TIMEOUT*":
                        timeoutCleanup()
                        break

        # EXIT PROGRAM AND RETURN TO TERMINAL
        if user_cmd == "x":
            os.system('cls' if os.name == 'nt' else 'clear')
            break

        # EXIT BECAUSE OF TIMEOUT
        if user_cmd == "*TIMEOUT*":
            timeoutCleanup()
            break
        
        os.system('cls' if os.name == 'nt' else 'clear')


if hashed_pass == False:
    print ("Incorrect master passsword.")
