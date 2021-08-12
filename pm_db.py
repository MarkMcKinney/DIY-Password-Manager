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

'''
ChangeLog by aarana14:
 + Added main function to run program, allowing more flexibility to allow user to input master password more than once if they messed up. Also better syntax.
 + Added ability to return to menu if "add profile" is selected without having to input anything
 + Cleaned up boolens
 + main_pwd_manager added to run the manager inside a function that can be called up
 + fileSetup() lods up salting and verifier
 + Added all manager functions as methods for better syntax, flexibility, readibility, and editability
'''

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

def main():
    #RUN PROGRAM
    # RUN LOGIN
    print(lockImg)
    hashed_pass = False
    cSALT, cVERIFIER, dataBase = fileSetup()
    while not hashed_pass:
        entered_pass = getpass.getpass("Enter Master Key: ")
        hashed_pass = verify_password(entered_pass, cSALT, cVERIFIER) # Require password to be entered
        if not hashed_pass:
            print ("Incorrect master password. Try again.\n")
    if hashed_pass:
        main_pwd_manager(hashed_pass, dataBase)

def main_pwd_manager(hashed_pass, contents):
    os.system('cls' if os.name == 'nt' else 'clear')
    db = json.loads(decrypt_data(contents,hashed_pass).decode('utf-8'))
    timedOut = False
    while not timedOut:
        print(checkImg)
        print (divider)
        user_cmd = print("\n(a)dd profile | (f)ind profile data  | (e)dit profile data | (r)ead all profiles | (d)elete profile data\n(g)enerate password | e(x)it\n\nWhat would you like to do? ")
        user_cmd = timeoutInput('', '*TIMEOUT*') 
        print("\n")
        
        #Add Profile
        if user_cmd == "a":
            timedOut = addProfile(hashed_pass, db)

        # READ PROFILE
        if user_cmd == "f":
            timedOut = findProfileData(hashed_pass, db)

        # READ ALL PROFILES
        if user_cmd == "r":
            timedOut = readAllProfiles(hashed_pass, db)

        # EDIT PROFILE
        if user_cmd == "e":
            timedOut = editProfileData()

        # DELETE PROFILE
        if user_cmd == "d":
            timedOut = deleteProfileData(hashed_pass, db)

        # GENERATE PASSWORD
        if user_cmd == "g":
            timedOut = pwdGenerate(hashed_pass, db)

        # EXIT PROGRAM AND RETURN TO TERMINAL
        if user_cmd == "x":
            os.system('cls' if os.name == 'nt' else 'clear')
            timedOut = True

        # EXIT BECAUSE OF TIMEOUT
        if user_cmd == "*TIMEOUT*":
            timeoutCleanup()
            timedOut = True
        
        os.system('cls' if os.name == 'nt' else 'clear')

def addProfile(hashed_pass, db):
    # ADD PROFILE
    displayHeader("ADD A PROFILE")
    print("Type and submit (.c) to cancel.")
    print("Website domain name:")
    add_domain = timeoutInput("","*TIMEOUT*")
    if add_domain == "*TIMEOUT*":
        timeoutCleanup()
        return True
    if (add_domain != ".c"): #Cancel if mind is changed
        print("Username:")
        add_user = timeoutInput("","*TIMEOUT*")
        if add_user == "*TIMEOUT*":
            timeoutCleanup()
            return True
        print("Password:")
        add_password = timeoutInput("","*TIMEOUT*")
        if add_password == "*TIMEOUT*":
            timeoutCleanup()
            return True
    if (add_domain != ".c"):
        db[add_domain] = {"username":str(encrypt_data(add_user,hashed_pass).decode('utf-8')),"password":str(encrypt_data(add_password,hashed_pass).decode('utf-8'))}
        overwrite_db(encrypt_data(json.dumps(db),hashed_pass).decode('utf-8'))
        print("Created "+add_domain+" profile successfully!")
    else:
        print("Operation canceled.")
    print("\nPress (m) to return to menu...")
    userContinue = timeoutInput("","*TIMEOUT*")
    if userContinue == "*TIMEOUT*":
        timeoutCleanup()
        return True
    print("Returning to Menu")
    return False

def findProfileData(hashed_pass, db):
    displayHeader("FIND A PROFILE")
    print("Type and submit (.c) to cancel.")
    print("What's the domain you're looking for?")
    read_domain = timeoutInput("","*TIMEOUT*")
    if read_domain == "*TIMEOUT*":
        timeoutCleanup()
        return True
    if read_domain != ".c":              
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
            return True
        return False
    else: #No timeout needed as this is an imediate action after cancelation
        print("Operation canceled.")
        print("\nReturning to Menu")
        return False

def editProfileData(hashed_pass, db):
    displayHeader("EDIT A PROFILE")
    print("Website domain name (submit (.c) to cancel): ")
    edit_domain = timeoutInput("","*TIMEOUT*")
    if edit_domain == "*TIMEOUT*":
        timeoutCleanup()
        return True
    if edit_domain != ".c":
        try:
            domain_info = db[edit_domain]
            curr_user = str(decrypt_data(bytes(domain_info['username'], encoding='utf-8'),hashed_pass).decode('utf-8'))
            curr_password = str(decrypt_data(bytes(domain_info['password'], encoding='utf-8'),hashed_pass).decode('utf-8'))

            print("New Username (submit (.c) to keep the current: "+curr_user+"):")
            edit_user = timeoutInput("","*TIMEOUT*")
            if edit_user == "*TIMEOUT*":
                timeoutCleanup()
                return True
            if edit_user == ".c":
                edit_user = ""
            if edit_user == "" or edit_user == " ":
                edit_user = curr_user
            
            print("New Password (submit (.c) to keep the current: "+curr_password+"):")
            edit_password = timeoutInput("","*TIMEOUT*")
            if edit_password == "*TIMEOUT*":
                timeoutCleanup()
                return True
            if edit_password == ".c":
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
                return True
        except:
            print ("This domain does not exist, changing to adding to new profile")
            print("\nType and submit (m) to return to menu...")
            userContinue = timeoutInput("","*TIMEOUT*")
            if userContinue == "*TIMEOUT*":
                timeoutCleanup()
                return True
            return False
    else:
        print("Returning to menu")
        return False

def readAllProfiles(hashed_pass, db):
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
        return True
    return False

def deleteProfileData(hashed_pass, db):
    displayHeader("DELETE A PROFILE")
    print("Write the exact saved domain name (type (.c) to cancel): ")
    del_domain = timeoutInput("","*TIMEOUT*")
    if del_domain == "*TIMEOUT*":
        timeoutCleanup()
        return True
    if del_domain != ".c":
        try:
            del db[del_domain]
            overwrite_db(encrypt_data(json.dumps(db),hashed_pass).decode('utf-8'))
            print ("Deleted "+del_domain+" profile successfully!")
            print("\nType and submit (m) to return to menu...")
            userContinue = timeoutInput("","*TIMEOUT*")
            if userContinue == "*TIMEOUT*":
                timeoutCleanup()
                return True
        except:
            print ("Unable to find "+del_domain)
            print("\nType and submit (m) to return to menu...")
            userContinue = timeoutInput("","*TIMEOUT*")
            if userContinue == "*TIMEOUT*":
                timeoutCleanup()
                return True
            return False
    else:
        print("Returning to menu...")
        return False

def pwdGenerate(hashed_pass, db):
    displayHeader("GENERATE RANDOM PASSWORD")
    print("How long would like your password (type (c) to cancel): ")
    pass_length = str(timeoutInput("","*TIMEOUT*"))
    if pass_length == "*TIMEOUT*":
        timeoutCleanup()
        return True
    if pass_length != ".c":
        try:
            if int(pass_length) < 6:
                pass_length = str(12)
                print("\nPasswords must be at least 6 characters long.")            
            print("\nYour "+pass_length+" Character Password: "+generate_password(int(pass_length)))
            print("\nType and submit (m) to return to menu...")
            userContinue = timeoutInput("","*TIMEOUT*")
            if userContinue == "*TIMEOUT*":
                timeoutCleanup()
                return True
        except:
            print("Unable to generate password.")
            userContinue = timeoutInput("","*TIMEOUT*")
            print("\nType and submit (m) to return to menu...")
            if userContinue == "*TIMEOUT*":
                timeoutCleanup()
                return True
            return False
        else:
            print("Returning to menu")
            return False

def fileSetup():
    with open("SALT.txt", 'rb') as readfile:
        content1 = readfile.read()
        readfile.close()
    cSALT = content1

    with open("VERIFIER.txt", 'rb') as readfile:
        content2 = readfile.read()
        readfile.close()
    cVERIFIER = content2

    file_path = "pm_db.mmf"
    file = open(file_path, "rb")
    content3 = file.read()
    dataBase = content3

    return cSALT, cVERIFIER, dataBase

def displayHeader(title):
    os.system('cls' if os.name == 'nt' else 'clear')
    print(checkImg)
    print(divider)
    print(str(title) + "\n")

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

def verify_password(password_provided, cSALT, cVERIFIER):
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

#PROFILE OPERATIONS
def overwrite_db(new_contents):
    file = open("pm_db.mmf", "w+")
    file.write(new_contents)
    file.close()


if __name__ == "__main__":
    main()