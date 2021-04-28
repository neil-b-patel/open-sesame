#################
##  LIBRARIES  ##
#################

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.kbkdf import (
    CounterLocation, KBKDFHMAC, Mode)
from gooey import Gooey, GooeyParser
from mysql.connector import Error
from dotenv import load_dotenv, set_key, dotenv_values
from os.path import join, dirname
import base64
import mysql.connector
import os

#################
##  CONSTANTS  ##
#################

HOST = "localhost"
DB_NAME = "passManager"


#################
##  LOAD .ENV  ##
#################

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)


############
##  TODO  ##
############
# BEN => generate user-specific secrets, store/read secrets in master table, encrypt/hash passwords
# ABBY => storing secrets in master table, SQL for add/get/update/delete funcs, secure way to deploy/host database, sanitize inputs
# NEIL => 5 subparsers for GUI (setup, login, add, get, update, delete)


##################
##  INIT FUNCS  ##
##################

def generate_env():
    ''' generates an .env file with user-specified username/password for DB connection '''

    username = ""
    password = ""

    # prompt user for DB user/password
    while len(username) < 1:
        username = input("Enter a database username (minimum 1 char): ")

    while len(password) < 1:
        password = input("Enter a database password (minimum 1 char): ")
    
    # write selected DB username/password and constant host/db_name to ENV vars 
    os.environ["HOST"] = HOST
    os.environ["USER"] = username.strip()
    os.environ["PASS"] = password.strip()
    os.environ["DB_NAME"] = DB_NAME

    # write selected DB username/password and constant host/db_name to .env
    set_key(dotenv_path, "HOST", HOST)
    set_key(dotenv_path, "USER", username.strip())
    set_key(dotenv_path, "PASS", password.strip())
    set_key(dotenv_path, "DB_NAME", DB_NAME)
    

def is_valid_env():
    ''' checks if the .env file is valid (for our purposes) '''

    env_vars = dotenv_values(".env")
    for var in env_vars:
        if len(env_vars[var]) < 1:
            print("Missing environment variables for DB connection...") 
            return False
    return True


def init():
    ''' initializes the app for first-time users '''

    # check for valid .env or generate it
    if not is_valid_env():
        generate_env()

    try:
        # connect to MySQL server
        db = mysql.connector.connect(
            host = os.environ["HOST"],
            user = os.environ["USER"],
            passwd = os.environ["PASS"]
        )

        # check for existing database
        cursor = db.cursor()
        cursor.execute("SHOW DATABASES")
        db_exists = False
        for item in cursor:
            if os.environ["DB_NAME"].lower() in item:
                db_exists = True

        # database not found, setting up database and tables
        if not db_exists:
            # create a database
            cursor.execute("CREATE DATABASE {}".format(os.environ["DB_NAME"]))

            # create a user_table
            # TODO: Abby, please check if this right! -Neil
            cursor.execute("CREATE TABLE user_table (username VARCHAR(100) PRIMARY KEY, eutk INT, eKEK INT, ev INT, salt INT, esk INT)")
        
        # close the DB cursor and connection
        cursor.close()
        db.close()
        return True

    except Error as e:
        print(f"The error '{e}' occurred")

    return False


####################
##  HELPER FUNCS  ##
####################

def create_connection():
    ''' creates a connection to the MySQL DB '''

    connection = None

    try:
        connection = mysql.connector.connect(
            host=os.environ["HOST"],
            user=os.environ["USER"],
            passwd=os.environ["PASS"],
            database=os.environ["DB_NAME"]
        )
        print("Connection to MySQL DB successful!")

    except Error as e:
        print(f"The error '{e}' occurred")

    return connection


def generate_master_key(master_password, salt):
    ''' generates a master_key used for verifying user authentication '''

    # master_password - user supplied master password. The pm does not store this, the user must remember it.
    # this is generated only once per user, it needs to be stored in order to regenerate the master key for authentication

    # CONVERT MASTER PASSWORD INTO BYTES ??
    # Password Based Key Derivation, a slow hashing function
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        )
    # derives the key from the password
    master_key = base64.urlsafe_b64encode(kdf.derive(master_password))
    f = Fernet(master_key)
    # RETURN TO ENCRYPT_USER_TABLE TO SEND TO TABLE ?

    return f


def generate_user_table_key(KEK):
    ''' generates a key to encrypt passwords added to the user_table '''

    kdf = KBKDFHMAC(
     algorithm=hashes.SHA256(),
     mode=Mode.CounterMode,
     length=32,
     rlen=4,
     llen=4,
     location=CounterLocation.BeforeFixed,
     label=label,
     context=context,
     fixed=None)
    user_table_key = kdf.derive(KEK)
    return user_table_key


#TODO is this not just ^ ?? -Neil
def generate_service_table_key():
    '''INSERT FUNCTION DESCRIPTION'''

    key = Fernet.generate_key()
    service_table_key = Fernet(key)
    return service_table_key

    # Checks if user supplied password matches the stored one
    # also has added functionality of decrypting and saving the things we need,
        # stretch goal is that when app "terminates" the saved things are cleared from mem
    # DB done (I think)


#########################################
##  ACTIONS FOR UNAUTHENTICATED USERS  ##
#########################################

def create_user(master_password, username):
    ''' create a user with master_password, and make a user_table '''

    salt = os.urandom(16)
    key_encryption_key = generate_master_key(master_password, salt)
    user_table_key = generate_user_table_key(key_encryption_key)

    service_key = generate_service_table_key()
    
    # Need to store:
    username = username #TODO: is this needed? -Neil
    encrypted_user_table_key = key_encryption_key.encrypt(user_table_key)
    encyrpted_KEK = user_table_key.encrypt(key_encryption_key)
    encrypted_validator = user_table_key.encrypt(user_table_key)
    salt = salt #TODO: is this needed? -Neil
    encrypted_service_key = user_table_key.encrypt(service_key)

    # SEND EVERYTHING TO USER_TABLE
    connection = create_connection()
    cursor = connection.cursor()

    # TODO: Should we create a user_table here? -Neil

    # TODO: MENTION VARCHAR FOR USERNAME
    # TODO: are these strings or integers?
    cursor.execute("INSERT INTO user_table (username, eutk, eKEK, ev, salt, esk) VALUES (%s, %s, %s, %s, %s)",
                   (username, encrypted_user_table_key, encrypted_KEK, encrypted_validator, salt, encrypted_service_key))
    connection.commit()
    cursor.close()
    connection.close()

    return

    # Would have liked to use 'username' to seed as well
    # TODO: ASK


def authenticate_user():
    ''' authenticates a user if they supply a valid username and master_password '''

    # USER ENTERS USERNAME #
    # username =
    # attempted_pass = USER_ENTERED_MASTER_PASSWORD
    # SALT IS NOT ENCRYPTED WHEN ITS STORED!
    # grab: salt, encrypted_user_table_key,  grab encrypted validator

    connection = create_connection()
    cursor = connection.cursor()

    salt = cursor.execute(
        "SELECT salt FROM user_table WHERE username = (%s)", (username))
    encrypted_user_table_key = cursor.execute(
        "SELECT eutk FROM user_table WHERE username = (%s)", (username))
    encrypted_validator = cursor.execute(
        "SELECT ev FROM user_table WHERE username = (%s)", (username))

    connection.commit()
    cursor.close()
    connection.close()

    # KEK = generate_master_key(attepted_pass, salt)
    # table_key = KEK.decrypt(encrypted_user_table_key)
    # validator = KEKorTABLE_KEY.decrypt(encrypted_validator)

    # if validator == table_key:
        # VALID USER!
        # YAY :)
        # Save decrypted values of the database. So technically the table on our computers will never hold something that is decrypted
        # Instead we load the decrypted values into memory for access (we do that here) (we have to acknowledge that having it in memory is a threat)
        # TODO: SAVE WHERE?
        # save KEK for this session (true_KEK = table_key.decrypt(encrypted_KEK), also check if true_KEK==KEK that we just calculated)
        # save user_table_key
        # decrypt(service_table_key) and save it
    # else:
        # NOT A VALID USER!
        # NAY :(
    

    # TODO: Can we have this function return True or False? so we can use it to authenticate in main()? -Neil
    return


#####################################
## ACTIONS FOR AUTHENTICATED USERS ##
#####################################

def add_service(service, username, password, KEK):
    ''' add a login (service, username, password) to be saved in the password manager '''

    # generate random key, encrypt password with that key, encrypt key with kek, send to db
    key = Fernet.generate_key()
    f = Fernet(key)
    encrypted_pass = f.encrypt(password)
    # KEK = get KEK
    # encrypted_key = KEK.encrypt(f)
    # what?
    # call function that sends to db, that function will encrypt using service_key

    # for each service we store service, username, encrypted_pass, encrypted_key
    return


# TODO: Is this not just get_service down below? -Neil
# TODO: do we want to stick with xyz_login() or xyz_service()? -Neil
def get_login(service, username):
    ''' retrieve the password for the given service and username '''

    connection = create_connection()

    cursor = connection.cursor()

    # TODO: this users table may have to be changed
    cursor.execute(
        "SELECT User, Pass FROM users WHERE Service = (%s)", (service))

    login = cursor.fetchall()
    # password = decrypt(Pass)

    if(len(login) == 0):
        print('Credentials not found \n')
        # TODO: make sure this doesn't fuck stuff up
        cursor.close()
        connection.close()

    else:
        print('Credentials found: \n')
        cursor.close()
        connection.close()
        return login


def get_service(service, username, user_table_key, KEK):
    ''' get the login that matches the given service and username '''

    # if service in table service
    # grab value stored in encrypted_pass and encrypted_key

    # KEK = get KEK
    # key = KEK.decrypt(encrypted_key)
    # password = key.decrypt(encrypted_pass)

    return #password


def update_service(service, username, new_password):
    ''' update the login that matches the given service and username with the given password'''

    # use service/username to find the right entry
    # ENCRYPT
    # update the entry's password with the new_password

    return


def delete_service(service, username):
    ''' delete the login that matches the given service and username '''

    # use service/username to find the right entry
    # delete the entry

    return


###########################
##  APPLICATION WRAPPER  ##
###########################

@Gooey(program_name='open-sesame')  # attach Gooey to our code
def main():
    print()
    if not init():
        return

    parser = GooeyParser()                      # main app
    subs = parser.add_subparsers()              # add functions to the app
    setup_parser = subs.add_parser('setup')     # add the "setup acount" function
    login_parser = subs.add_parser('login')     # add the "login account" function
    add_parser = subs.add_parser('add')         # add the "add password" function
    get_parser = subs.add_parser('get')         # add the "get password" function
    update_parser = subs.add_parser('update')   # add the "update password" function
    delete_parser = subs.add_parser('delete')   # add the "delete password" function

    # add argument groups for each parser
    # add_parser.add_argument_group()

#     # add user input fields for function parameters
#     add_parser.add_argument('Service', widget='Textarea', gooey_options={
#         'initial_value': 'Backrub'
#     })
#     add_parser.add_argument('Username', widget='Textarea', gooey_options={
#         'initial_value': 'elliot_alderson'
#     })
#     add_parser.add_argument('Password', widget='Textarea', gooey_options={
#         'initial_value': 'eXamp!e_102'
#     })

#     get_parser.add_argument('Service', widget='Textarea', gooey_options={
#         'initial_value': 'Backrub'
#     })

#     args = vars(parser.parse_args())    # initialize app

#     # Checkpoint: will need to change to account for add_service and add_user. FIX BELOW
#     if len(args) > 1:   # add password
#         print('Encrypting password ...')
#         ##   NEW USER ALERT!! ##
#         ##     ENCRYPTING     ##
#         ## HASH PASSWORD HERE ##

#         new_pass = bytes(args['Password'], 'utf-8')
#         master_key = generate_master_key(new_pass, args['Username'])

#         service, username, password = args['Service'], args['Username'], master_key
#         add_login(service, username, password)
#         print('Credentials stored \n')
#     else:   # get password
#         service = args['Service']
#         print('Searching for {} ...'.format(service))
#         creds = get_login(service)
#         if creds:
#             print('\tService \t\t=>\t {} \n \tUsername \t=>\t {} \n \tPassword \t=>\t {}'.format(
#                 service, creds[0][0], creds[0][1]))


main()
