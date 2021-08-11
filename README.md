![DIY Password Manager Screenshot](banner.png)

# Password Manager
I built this to strengthen my cryptography skills and knowledge of data types in Python. This Password Manager doesn't keep your master password. Instead, valid passwords are determined if it decrypts a known string correctly. Typically, the salt and verifier hashes would be kept in a secure database. However, for educational purposes, I've kept them in text files. 

I'd love to hear from you about where I could improve it!

**EDIT (8/10/2021):** After posting this on [r/Python](https://www.reddit.com/r/Python/comments/p22p35/i_made_a_password_manager_for_the_terminal_let_me/), one Redditor asked what my threat model was. Initially, I had no idea what they were referring to, but after some research, I think this was the mental version I had of a threat model. I wanted to accomplish two things:

1. Make sure that all logins were encrypted, but editable.
2. That the master key wasn’t stored in any form.

This was done by encrypting JSON that contained logins, having all hashes and salts created with as much randomness as possible, and having an encrypted verifier string that the program knew what the decrypted version was.

## Instructions
Run the god_key_hasher.py file and enter your desired master password. You can access your new vault by running the pm_db.py file and entering your master password.

## Demo
You can run the demo by opening the pm_db.py file and using **thisisatest!** as the password.

## Disclaimer
This was built for educational purposes. This should not be used as your password manager. This software is provided as is and I do not take any responsibility for any damage or loss done with or by it.
