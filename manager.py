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
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

#################
##  CONSTANTS  ##
#################

HOST = "localhost"
DB_NAME = "passManager"


#################
##  LOAD .ENV  ##
#################

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path, override = True)


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

    # TODO: convert encrypted passwords to strings before storing in db, convert encrypted keys
def init():
    ''' initializes the app for first-time users '''

    # check for valid .env or generate it
    if not is_valid_env():
        generate_env()

    try:
        # connect to MySQL server
        db = mysql.connector.connect(
            host=os.environ["HOST"],
            user=os.environ["USER"],
            passwd=os.environ["PASS"]
        )

        # check for existing database
        cursor = db.cursor()
        cursor.execute("SHOW DATABASES")
        db_exists = False
        for item in cursor:
            if os.environ["DB_NAME"].lower() == item[0].lower():
                db_exists = True

        # database not found, setting up database and tables
        if not db_exists:
            # create a database
            print("creating a database")
            cursor.execute("CREATE DATABASE {}".format(os.environ["DB_NAME"]))

            cursor.execute("USE {}".format(os.environ["DB_NAME"]))

            # create a user_table
            # Abby, please check if this right! -Neil | yuh - Abby
            cursor.execute(
                "CREATE TABLE user_table (username VARCHAR(100) PRIMARY KEY, eutk TEXT, eKEK TEXT, ev TEXT, esk TEXT)")

    # for each service we store service, username, encrypted_pass, encrypted_key
    #TODO: are these strings or ints | if it's a key == Fernet(object),
    ## ep, if bytes, string_rep = base64.urlsafe_b64decode(encrypted_pass)
            cursor.execute(
                "CREATE TABLE services (username VARCHAR(100), service VARCHAR(100), ep TEXT, ek TEXT, PRIMARY KEY(username, service));")
        # close the DB cursor and connection
        #connection.commit()
        db.commit()
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


def generate_master_key(master_password):
    ''' generates a master_key used for verifying user authentication '''
    # master_password - user supplied master password. The pm does not store this, the user must remember it.
    # this is generated only once per user, it needs to be stored in order to regenerate the master key for authentication

    # Password Based Key Derivation, a slow hashing function
    otherinfo = b"concatkdf-example"
    ckdf = ConcatKDFHash(
    algorithm=hashes.SHA256(),
     length=32,
     otherinfo=otherinfo,)

    safely = str.encode(master_password)
    master_key = base64.urlsafe_b64encode(ckdf.derive(safely))
    return master_key


def generate_user_table_key(KEK):
    ''' generates a key to encrypt passwords added to the user_table '''
    # key-based key derivation
    kdf = KBKDFHMAC(
        algorithm=hashes.SHA256(),
        mode=Mode.CounterMode,
        length=32,
        rlen=4,
        llen=4,
        location=CounterLocation.BeforeFixed,
        label=  b"KBKDF HMAC Label",
        context=b"KBKDF HMAC Context",
        fixed=None)
    key = kdf.derive(KEK)
    #print("KEY DERIVED FROM GENERATE USER KEY: " , key)
    #user_table_key = Fernet(key)
    return key


# TODO is this not just ^ ?? -Neil | No -ben
def generate_service_table_key():
    '''INSERT FUNCTION DESCRIPTION'''

    key = Fernet.generate_key()
    #service_table_key = Fernet(key)
    return key


#########################################
##  ACTIONS FOR UNAUTHENTICATED USERS  ##
#########################################

def create_user(username, master_password):
    ''' create a user with master_password, and make a user_table '''

    #salt = os.urandom(16)
    key_encryption_key = generate_master_key(master_password)
    user_table_key = generate_user_table_key(key_encryption_key)
    service_key = generate_service_table_key()
    # ^ all bytes

    KEK = Fernet(key_encryption_key)
    b64_user_table_key = base64.urlsafe_b64encode(user_table_key)
    UTK = Fernet(b64_user_table_key)
    # ^ makes them fernet objects used to encrypt


    encrypted_user_table_key = KEK.encrypt(user_table_key)
    encrypted_KEK = UTK.encrypt(key_encryption_key)
    encrypted_validator = UTK.encrypt(user_table_key)
    encrypted_service_key = UTK.encrypt(service_key)

    # CONVERT TO STRINGS
    str_encrypted_user_table_key = bytes.decode(encrypted_user_table_key)
    str_en_KEK = bytes.decode(encrypted_KEK)
    str_en_validator = bytes.decode(encrypted_validator)
    str_en_service_key = bytes.decode(encrypted_service_key)
    #str_salt = bytes.decode(salt)
    #str_salt = str(salt)

    # SEND EVERYTHING TO USER_TABLE
    connection = create_connection()
    cursor = connection.cursor()

    #print("before db esk is: " , str_en_service_key)

    #str_salt = str_salt[1:-1]
    #print("before db str_salt is: ", str_salt)




    # TODO: MENTION VARCHAR FOR USERNAME
    # TODO: are these strings or integers?
    cursor.execute("INSERT INTO user_table (username, eutk, eKEK, ev, esk) VALUES (%s, %s, %s, %s, %s)",
                   (username, str_encrypted_user_table_key, str_en_KEK, str_en_validator, str_en_service_key))
    connection.commit()
    cursor.close()
    connection.close()

    return


def authenticate_user(username, master_password):
    ''' authenticates a user if they supply a valid username and master_password '''

    # USER ENTERS USERNAME #
    # attempted_pass = USER_ENTERED_MASTER_PASSWORD
    # SALT IS NOT ENCRYPTED WHEN ITS STORED!
    # grab: salt, encrypted_user_table_key,  grab encrypted validator

    connection = create_connection()
    cursor = connection.cursor()



    cursor.execute(
        "SELECT esk FROM user_table WHERE username = (%s)", (username,))

    esk = cursor.fetchone()

    cursor.execute(
        "SELECT eKEK FROM user_table WHERE username = (%s)", (username,))

    eKEK = cursor.fetchone()

    cursor.execute(
        "SELECT eutk FROM user_table WHERE username = (%s)", (username,))

    encrypted_user_table_key = cursor.fetchone()

    cursor.execute(
        "SELECT ev FROM user_table WHERE username = (%s)", (username,))

    encrypted_validator = cursor.fetchone()

    connection.commit()
    cursor.close()
    connection.close()


    encrypted_user_table_key = str.encode(encrypted_user_table_key[0])
    encrypted_validator = str.encode(encrypted_validator[0])
    byte_KEK = generate_master_key(master_password)
    KEK = Fernet(byte_KEK)
    attempted_utk = generate_user_table_key(byte_KEK)
    supposed_eutk = KEK.encrypt(attempted_utk)

    table_key = KEK.decrypt(encrypted_user_table_key)
    b64_UTK = base64.urlsafe_b64encode(table_key)
    key_table_key = Fernet(b64_UTK)
    validator = key_table_key.decrypt(encrypted_validator)



    if validator == table_key:
    # VALID USER!
    # YAY :)
        # sanity check
        eKEK = str.encode(eKEK[0])
        decrypted_KEK = key_table_key.decrypt(eKEK)
        if decrypted_KEK == byte_KEK:
            byte_esk = str.encode(esk[0])
            decrypted_service_table_key = key_table_key.decrypt(byte_esk)
            return [True, decrypted_KEK, table_key, decrypted_service_table_key]

    return [False, None, None, None, None]
    #Debugging statements
    #print("salt before we str encode it " , salt)
    #print("SUPPOSED EUTK GENERATED SAME WAY AS BEFORE: ", supposed_eutk)
    #print("this is KEK!: " , byte_KEK)
    #true__en_kek = b"gAAAAABgi_nI5INEMpL2sgIHfYeuGYaDbQgDoFma6zntbKvfospRG-GncWhESQwMpjV9d-wEEtLqvLmVn9A-kwtCupA-_VdIdFNeB60VEQgLPwAkwCeFyuEtfsU7BQua0w3q7MgUgwnB"
    #print("THIS IS THE GENERATED KEK FROM THE ATTEMPTED MP: ", byte_KEK)
    #print("encrypted_user_table_key: " , encrypted_user_table_key)
    #print("validator: ", encrypted_validator)
    #print("salt before we str encode it " , salt)
    #print("this is the salt grabbed and encoded from db: " , salt)


#####################################
## ACTIONS FOR AUTHENTICATED USERS ##
#####################################

def add_service(service, username, password, KEK):
    ''' add a login (service, username, password) to be saved in the password manager '''
    print("this is kek: " , KEK)
    key_KEK = Fernet(KEK)
    key = Fernet.generate_key()
    encrypted_key = key_KEK.encrypt(key)
    str_en_key = bytes.decode(encrypted_key)
    f = Fernet(key)
    byte_pass = str.encode(password)
    encoded_pass = base64.urlsafe_b64encode(byte_pass)
    encrypted_pass = f.encrypt(encoded_pass)
    str_en_pass = bytes.decode(encrypted_pass)

    connection = create_connection()
    cursor = connection.cursor()

    cursor.execute("INSERT INTO services (username, service, ep, ek) VALUES (%s, %s, %s, %s)",
                   (username, service, str_en_pass, str_en_key))


    connection.commit()


    cursor.execute("SELECT COUNT(1) FROM services WHERE username  = (%s) AND service = (%s)", (username, service))


    count = cursor.fetchone()
    cursor.close()
    connection.close()

    if(count[0] == 0):
        return False
    else:
        return True


    # Can we have this function return True or False? so we can use it check if action was completed in main()? -Neil | done - Abby


# # TODO: Is this not just get_service down below? -Neil | Yes I said that remember - Abby
# # TODO: do we want to stick with xyz_login() or xyz_service()? -Neil
# def get_login(service, username):
#     ''' retrieve the password for the given service and username '''

#     connection = create_connection()

#     cursor = connection.cursor()

#     # TODO: this users table may have to be changed
#     cursor.execute(
#         "SELECT User, Pass FROM users WHERE Service = (%s)", (service))

#     login = cursor.fetchall()
#     # password = decrypt(Pass)

#     if(len(login) == 0):
#         print('Credentials not found \n')
#         # TODO: make sure this doesn't fuck stuff up
#         cursor.close()
#         connection.close()

#     else:
#         print('Credentials found: \n')
#         cursor.close()
#         connection.close()
#         return login


def get_service(service, username, user_table_key, KEK):
    ''' get the login that matches the given service and username '''

    # if service in table service
    connection = create_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(1) FROM services WHERE username  = (%s) AND service = (%s)", (username, service))

    count = cursor.fetchone()

    if(count[0] == 0):
        return None

    else:
        cursor.execute(
        "SELECT ep FROM services WHERE username = (%s) AND service = (%s)", (username, service))

        encrypted_pass = cursor.fetchone()

        cursor.execute(
        "SELECT ek FROM services WHERE username = (%s) AND service = (%s)", (username, service))

        encrypted_key = cursor.fetchone()


    connection.commit()
    cursor.close()
    connection.close()

    # Decryption
    byte_en_key = str.encode(encrypted_key[0])
    byte_en_pass = str.encode(encrypted_pass[0])
    decrypted_key = KEK.decrypt(byte_en_key)
    key = Fernet(decrypted_key)
    decrypted_pass = key.decrypt(byte_en_pass)
    password = base64.urlsafe_b64decode(decrypted_pass)

    return  [True,password]


def update_service(service, username, new_password, KEK):
    ''' update the login that matches the given service and username with the given password'''

     # use service/username to find the right entry

     # TODO: for ben- ENCRYPT (i guessed on the code below)
    connection = create_connection()
    cursor = connection.cursor()
    cursor.execute(
        "SELECT ek FROM services WHERE username = (%s) AND service = (%s)", (username, service))

    encrypted_key = cursor.fetchone()


    byte_en_key = str.encode(encrypted_key)
    decrypted_key = KEK.decrypt(byte_en_key)
    key = Fernet(decrypted_key)
    byte_pass = str.encode(new_password)
    encoded_pass = base64.urlsafe_b64encode(byte_pass)
    encrypted_pass = f.encrypt(encoded_pass)
    str_en_pass = bytes.decode(encrypted_pass)


    cursor.execute("UPDATE services SET ep = (%s)  WHERE username = (%s) AND service = (%s)", (str_en_pass,username, service))


    connection.commit()


    cursor.execute("SELECT ep FROM services WHERE username = (%s) AND service = (%s)", (username, service))

    new_ep = cursor.fetchone()


    cursor.close()
    connection.close()

    if(str_en_pass == new_ep[0]):
        return True

    else:
        return False

    # Can we have this function return True or False? so we can use it check if action was completed in main()? -Neil


def delete_service(service, username):
    ''' delete the login that matches the given service and username '''

    # delete the entry
    connection = create_connection()
    cursor = connection.cursor()

    cursor.execute("DELETE FROM services WHERE username = (%s) AND service = (%s)", (username, service))

    connection.commit()

    cursor.execute("SELECT COUNT(1) FROM services WHERE username  = (%s) AND service = (%s)", (username, service))

    count = cursor.fetchone()

    cursor.close()
    connection.close()

    if(count[0] == 0):
        return True
    else:
        return False

     #Can we have this function return True or False? so we can use it check if action was completed in main()? -Neil


###########################
##  APPLICATION WRAPPER  ##
###########################

# attach Gooey to our code
@Gooey(program_name='open-sesame', program_description='An open-source password manager sans Alibaba and the Forty Thieves', default_size=(550, 440), show_restart_button=False)
def main():
    # used for checking if a user is authenticated
    authenticated = False
    KEK = b''
    user_table_key = b''
    service_table_key = b''

    # initialize for first-time users
    if not init():
        return

    parser = GooeyParser()                          # main app
    subs = parser.add_subparsers(dest='command')    # main "function" for app

    # add "sub-functions" (sub-parsers) to the main "function" (parser)
    setup_parser = subs.add_parser('setup')
    login_parser = subs.add_parser('login')
    add_parser = subs.add_parser('add')
    get_parser = subs.add_parser('get')
    update_parser = subs.add_parser('update')
    delete_parser = subs.add_parser('delete')

    # add arguments (input fields) for parsers (functions)
    setup_group = setup_parser.add_argument_group("Setup an Account")
    setup_group.add_argument("Account Username")
    setup_group.add_argument("Master Password", widget="PasswordField")

    login_group = login_parser.add_argument_group("Login to Account")
    login_group.add_argument("Account Username")
    login_group.add_argument("Master Password", widget="PasswordField")

    add_group = add_parser.add_argument_group("Add Password")
    add_group.add_argument("Service")
    add_group.add_argument("Username")
    add_group.add_argument("Password", widget="PasswordField")

    get_group = get_parser.add_argument_group("Get Password")
    get_group.add_argument("Service")
    get_group.add_argument("Username")

    update_group = update_parser.add_argument_group("Update Password")
    update_group.add_argument("Service")
    update_group.add_argument("Username")
    update_group.add_argument("New Password", widget="PasswordField")

    delete_group = delete_parser.add_argument_group("Delete Password")
    delete_group.add_argument("Service")
    delete_group.add_argument("Username")

    # run app
    args = vars(parser.parse_args())
    cmd = args['command']


    # handle subfunctions and their args
    if cmd == 'setup':
        print("Creating account...")
        account_username = args['Account Username']
        #username = account_username.lower()
        master_password = args['Master Password']
        create_user(account_username, master_password)
        print("Account created!")
        print("You must still 'login.'")
        print()

    elif cmd == 'login':
        print("Authenticated flag: ", authenticated)
        print("Authenticating user...")
        account_username = args['Account Username']
        master_password = args['Master Password']
        secrets = authenticate_user(account_username, master_password)
        print(secrets)
        is_auth, KEK, user_table_key, service_table_key = secrets[0], secrets[1], secrets[2], secrets[3]

        if is_auth:
            print("User authenticated!")
            authenticated = True
        else:
            print("User authentication failed!")
            authenticated = False
        print()
        print("Authenticated flag: ", authenticated)


    else:
      #  authenticated = True
        if authenticated:
            if cmd == 'add':
                print("Encrypting password...")
                service = args['Service']
                username = args['Username']
                password = args['Password']
                is_added = add_service(service, username, password, KEK)
                print("Storing password...")
                if is_added:
                    print("Password added!")
                else:
                    print("Duplicate service/username pair exists, password not added.")
                print()

            elif cmd == 'get':
                print("Searching for password...")
                service = args['Service']
                username = args['Username']
                creds = (get_service(service, username, user_table_key, KEK))
                if creds:
                    print("Password found!")
                    print('\tService \t\t=>\t {} \n \tUsername \t=>\t {} \n \tPassword \t=>\t {}'.format(
                        service, username, creds[1]))
                else:
                    print('Password not found.')
                print()

            elif cmd == 'update':
                print("Updating password...")
                service = args['Service']
                username = args['Username']
                new_password = args['New Password']
                is_updated = update_service(service, username, new_password, KEK)
                if is_updated:
                    print("Password updated!")
                else:
                    print("Login not found, password not updated.")
                print()


            elif cmd == 'delete':
                print("Deleting password...")
                service = args['Service']
                username = args['Username']
                is_deleted = delete_service(service, username)
                if is_deleted:
                    print("Password deleted!")
                else:
                    print("Login not found, password not deleted.")
                print()

            else:
                print("INVALID COMMAND SELECTED!")
                print("How did you even do that??\n")
        else:
            print("User Authentication Error!")
            print("Returning users: Use 'login'")
            print("New users: Use 'setup' and then 'login'\n")


main()
