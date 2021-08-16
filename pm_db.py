import json
import base64
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
import getpass
import os
import threading
import difflib
import string
import secrets
import pyperclip
import time
from inputimeout import inputimeout, TimeoutOccurred
import keyboard as kb
"""
ChangeLog by aarana14:
 + Added main function to run program, allowing more flexibility to allow user to input master password more than once if they messed up. Also better syntax.
 + Added ability to return to menu if "add profile" is selected without having to input anything
 + Cleaned up boolens
 + main_pwd_manager added to run the manager inside a function that can be called up
 + fileSetup() lods up salting and verifier
 + Added all manager functions as methods for better syntax, flexibility, readibility, and editability
"""

divider = "-----------------------------------------------------------------------------------------------------------------------\n"
lockImg = """                               
                                   
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
                                                   
                                                                
    """
checkImg = """                               
                                   
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
                                                                                                       
    """

# Global Variables
timeoutGlobalCode = "*TIMEOUT*"

def main():
    # RUN PROGRAM
    # RUN LOGIN
    print(lockImg)
    hashed_pass = False
    cSALT, cVERIFIER, dataBase = fileSetup()
    while not hashed_pass:
        entered_pass = getpass.getpass("Enter Master Key: ")
        hashed_pass = verify_password(
            entered_pass, cSALT, cVERIFIER
        )  # Require password to be entered
        if not hashed_pass:
            print("Incorrect master password. Try again.\n")
    if hashed_pass:
        del entered_pass
        main_pwd_manager(hashed_pass, dataBase)


def main_pwd_manager(hashed_pass, contents):
    os.system("cls" if os.name == "nt" else "clear")
    db = json.loads(decrypt_data(contents, hashed_pass).decode("utf-8"))
    timedOut = False
    while not timedOut:
        os.system("cls" if os.name == "nt" else "clear")
        print(checkImg)
        print(divider)
        user_cmd = print(
            "\n(a)dd profile | (f)ind profile data  | (e)dit profile data | (r)ead all profiles | (d)elete profile data\n(g)enerate password | e(x)it\n"
        )
        user_cmd = timeoutInput("What would you like to do? ")
        print("\n")

        # Ensure user input is lowercase
        if user_cmd != timeoutGlobalCode:
            user_cmd = user_cmd.lower()

        # Add Profile
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
            timedOut = editProfileData(hashed_pass, db)

        # DELETE PROFILE
        if user_cmd == "d":
            timedOut = deleteProfileData(hashed_pass, db)

        # GENERATE PASSWORD
        if user_cmd == "g":
            timedOut = pwdGenerate(hashed_pass, db)

        # EXIT PROGRAM AND RETURN TO TERMINAL
        if user_cmd == "x":
            os.system("cls" if os.name == "nt" else "clear")
            timedOut = True

        # EXIT BECAUSE OF TIMEOUT
        if user_cmd == timeoutGlobalCode:
            timeoutCleanup()
            timedOut = True
            
    # CLEANUP SENSITIVE INFO ON TIMEOUT
    del hashed_pass
    del contents
    del db

def addProfile(hashed_pass, db):
    # ADD PROFILE
    displayHeader("ADD A PROFILE")
    print("Type and submit (.c) to cancel.")
    add_domain = timeoutInput("Website domain name: ")
    if add_domain != ".c":  # Cancel if mind is changed
        add_user = timeoutInput("Username: ")
        add_password = timeoutInput("Password: ")
    if add_domain != ".c":
        db[add_domain] = {
            "username": str(encrypt_data(add_user, hashed_pass).decode("utf-8")),
            "password": str(encrypt_data(add_password, hashed_pass).decode("utf-8")),
        }
        overwrite_db(encrypt_data(json.dumps(db), hashed_pass).decode("utf-8"))
        print("Created " + add_domain + " profile successfully!")
    else:
        print("Operation canceled.")
    timeoutInput("\nPress enter to return to menu...")
    print("Returning to Menu")
    return False


def findProfileData(hashed_pass, db):
    displayHeader("FIND A PROFILE")
    print("Type and submit (.c) to cancel.")
    read_domain = timeoutInput("What's the domain you're looking for? ")
    if read_domain != ".c":
        try:
            domains = list(db.keys())
            matches = difflib.get_close_matches(read_domain, domains)
            if matches:
                print("\nClosest match:\n")
                i = 1
                for d in matches:
                    domain_info = db[d]
                    username = str(
                        decrypt_data(
                            bytes(domain_info["username"], encoding="utf-8"),
                            hashed_pass,
                        ).decode("utf-8")
                    )
                    print("PROFILE " + str(i) + ": " + d)
                    del d
                    print("Username: " + username + "\n")
                    del domain_info
                    del username
                    i = i + 1
                userContinue = timeoutInput("\nSelect the password to be copied to your clipboard (ex: 1), or type (.c) to cancel: ")
                if userContinue.isdigit() == True:
                    if int(userContinue) > 0:
                        try:
                            password = str(
                                decrypt_data(
                                    bytes(db[str(matches[int(userContinue) - 1])]["password"], encoding="utf-8"),
                                    hashed_pass,
                                ).decode("utf-8")
                            )
                            print("\n" + to_clipboard(password))
                            del password
                        except:
                            print("\nUnable to find profile corresponding to " + str(userContinue) + ".")
                    else:
                        print("\nThere are no profiles corresponding to that number.")
                if userContinue.isdigit() == False:
                    return False
            else:
                print("Could not find a match. Try viewing all saved profiles.")
        except:
            print("Error finding profile.")
        userContinue = timeoutInput("\nPress enter to return to menu...")
        return False
    else:  # No timeout needed as this is an imediate action after cancelation
        print("Operation canceled.")
        print("\nReturning to Menu")
        return False


def editProfileData(hashed_pass, db):
    displayHeader("EDIT A PROFILE")
    edit_domain = timeoutInput("Website domain name (submit (.c) to cancel): ")
    if edit_domain != ".c":
        try:
            domain_info = db[edit_domain]
            curr_user = str(
                decrypt_data(
                    bytes(domain_info["username"], encoding="utf-8"), hashed_pass
                ).decode("utf-8")
            )
            curr_password = str(
                decrypt_data(
                    bytes(domain_info["password"], encoding="utf-8"), hashed_pass
                ).decode("utf-8")
            )

            edit_user = timeoutInput("New Username (submit (.c) to keep the current: " + curr_user + "): ")
            if edit_user == ".c":
                edit_user = ""
            if edit_user == "" or edit_user == " ":
                edit_user = curr_user

            edit_password = timeoutInput("New Password (submit (.c) to keep the current: " + curr_password + "): ")
            if edit_password == ".c":
                edit_password = ""
            if edit_password == "" or edit_password == " ":
                edit_password = curr_password

            db[edit_domain] = {
                "username": str(encrypt_data(edit_user, hashed_pass).decode("utf-8")),
                "password": str(
                    encrypt_data(edit_password, hashed_pass).decode("utf-8")
                ),
            }
            overwrite_db(encrypt_data(json.dumps(db), hashed_pass).decode("utf-8"))
            print("Updated " + edit_domain + " profile successfully!")
            del edit_domain
            del curr_user
            del edit_user
            del curr_password
            del edit_password
            del db
            userContinue = timeoutInput("\nPress enter to return to menu...")
            print("Returning to menu")
            return False
        except:
            print("This domain does not exist, changing to adding to new profile")
            userContinue = timeoutInput("\nPress enter to return to menu...")
            return False
    else:
        print("Returning to menu")
        return False


def readAllProfiles(hashed_pass, db):
    displayHeader("READING ALL PROFILES")
    try:
        i = 0
        domains = list(db.keys())
        for e in db:
            i = i + 1
            username = str(
                decrypt_data(
                    bytes(db[e]["username"], encoding="utf-8"), hashed_pass
                ).decode("utf-8")
            )
            print("PROFILE " + str(i) + ": " + e)
            print("Username: " + username)
            del e
            del username
            print(divider)
        if i == 0:
            print("No saved profiles")
        if i > 0:
            userContinue = timeoutInput("\nSelect the password to be copied to your clipboard (ex: 1), or type (.c) to cancel: ")
            if userContinue.isdigit() == True:
                if int(userContinue) > 0:
                    try:
                        password = str(
                            decrypt_data(
                                bytes(db[str(domains[int(userContinue) - 1])]["password"], encoding="utf-8"),
                                hashed_pass,
                            ).decode("utf-8")
                        )
                        print("\n" + to_clipboard(password))
                        del password
                    except:
                        print("\nUnable to find profile corresponding to " + str(userContinue) + ".")
                else:
                    print("\nThere are no profiles corresponding to that number.")
            if userContinue.isdigit() == False and userContinue != timeoutGlobalCode:
                return False
            
    except:
        print("Could not load all profiles")
    userContinue = timeoutInput("\nPress enter to return to menu...")
    return False


def deleteProfileData(hashed_pass, db):
    displayHeader("DELETE A PROFILE")
    del_domain = timeoutInput("Write the exact saved domain name (type (.c) to cancel): ")
    if del_domain != ".c":
        try:
            del db[del_domain]
            overwrite_db(encrypt_data(json.dumps(db), hashed_pass).decode("utf-8"))
            print("Deleted " + del_domain + " profile successfully!")
            userContinue = timeoutInput("\nPress enter to return to menu...")
            print("Returning to menu")
            return False
        except:
            print("Unable to find " + del_domain)
            userContinue = timeoutInput("\nPress enter to return to menu...")
            print("Returning to menu")
            return False
    else:
        print("Returning to menu...")
        return False


def pwdGenerate(hashed_pass, db):
    displayHeader("GENERATE RANDOM PASSWORD")
    pass_length = str(timeoutInput("Password length (type (.c) to cancel): "))
    if pass_length != ".c":
        try:
            if int(pass_length) < 6:
                pass_length = str(12)
                print("\nPasswords must be at least 6 characters long.")
            print(to_clipboard(str(generate_password(int(pass_length)))))
            userContinue = timeoutInput("\nPress enter to return to menu...")
            print("Returning to menu")
            return False
        except:
            print("Unable to generate password.")
            userContinue = timeoutInput("\nPress enter to return to menu...")
            print("Returning to menu")
            return False
    else:
        print("Returning to menu")
        return False


def fileSetup():
    with open("SALT.txt", "rb") as readfile:
        content1 = readfile.read()
        readfile.close()
    cSALT = content1

    with open("VERIFIER.txt", "rb") as readfile:
        content2 = readfile.read()
        readfile.close()
    cVERIFIER = content2

    file_path = "pm_db.mmf"
    file = open(file_path, "rb")
    content3 = file.read()
    dataBase = content3

    return cSALT, cVERIFIER, dataBase


def displayHeader(title):
    os.system("cls" if os.name == "nt" else "clear")
    print(checkImg)
    print(divider)
    print(str(title) + "\n")


# Clear clipboard after 30 seconds
def clear_clipboard_timer():
    kb.wait('ctrl+v')
    time.sleep(0.1) # Without sleep, clipboard will automatically clear before user actually pastes content
    pyperclip.copy("")


# Put string in clipboard
def to_clipboard(input_to_copy):
    pyperclip.copy(str(input_to_copy))
    threading.Thread(target=clear_clipboard_timer).start()
    return "Password was saved to clipboard. It will be removed from your clipboard as soon as you paste it."
    

# TIMEOUT
def timeoutCleanup():
    os.system("cls" if os.name == "nt" else "clear")
    print(lockImg)
    print(
        "\n\nYour session expired. For your security, the program has automatically exited. All submitted data is still saved."
    ) 
    exit


def timeoutInput(caption):
    try:
        user_input = inputimeout(prompt=caption, timeout=90)
    except TimeoutOccurred:
        user_input = timeoutGlobalCode
        timeoutCleanup()
    return(user_input)


# CRYPTOGRAPHY FUNCTIONS

# Generate random password - user cannot request passwords that are less than 6 characters
# use secrets instead of random (secrets is safer)
def generate_password(length=12):
    if length < 6:
        length = 12
    uppercase_loc = secrets.choice(string.digits)  # random location of lowercase
    symbol_loc = secrets.choice(string.digits)  # random location of symbols
    lowercase_loc = secrets.choice(string.digits)  # random location of uppercase
    password = ""
    pool = string.ascii_letters + string.punctuation  # the selection of characters used
    for i in range(length):
        if i == uppercase_loc:  # this is to ensure there is at least one uppercase
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
    return encrypted


def decrypt_data(input, hashed_pass):
    f = Fernet(hashed_pass)
    decrypted = f.decrypt(input)
    return decrypted


def verify_password(password_provided, cSALT, cVERIFIER):
    verifier = cVERIFIER
    # Hash password for later comparison
    password = password_provided.encode()  # Convert to type bytes
    salt = cSALT
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    hashed_entered_pass = base64.urlsafe_b64encode(
        kdf.derive(password)
    )  # Can only use kdf once

    try:
        pass_verifier = decrypt_data(verifier, hashed_entered_pass)
        if pass_verifier == b"entered_master_correct":
            return hashed_entered_pass
    except:
        return False


# PROFILE OPERATIONS
def overwrite_db(new_contents):
    file = open("pm_db.mmf", "w+")
    file.write(new_contents)
    file.close()


if __name__ == "__main__":
    main()
