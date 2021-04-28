from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from gooey import Gooey, GooeyParser
import mysql.connector
import os
import base64
from mysql.connector import Error
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.kbkdf import (CounterLocation, KBKDFHMAC, Mode)


# TODO:
# BEN => hash passwords
# ABBY => store credentials in database (SQL) instead of "dev_db" file (done) database-end master password, secure way to deploy/host database, sanitize inputs
# NEIL => GUI (done) application-end master password, add functionality for changing existing passwords

# does sql create a vulnerability? Do we have to parse it or whatever its called? does the database get hosted locally?

# If MP correct (more detail below), they will be able to add new services/passwords and get passwords from existing service
def create_connection(host_name, user_name, user_password, db_name):

    connection = None
    try:
        connection = mysql.connector.connect(
            host=host_name,
            user=user_name,
            passwd=user_password,
            database=db_name
        )
        print("Connection to MySQL DB successful")

    except Error as e:
        print(f"The error '{e}' occurred")

    return connection

    #TODO: Is this still needed?
    # We need add_login and add_service to be two seperate functions i think
    # def add_login(service, username, password):
    # # Throws error when adding a repeat service/username. We probably need something to handle changing a password for existing service
    # print('Storing credentials ...')
    #                                     #TODO: ADD ENV VARIABLE
    # connection = create_connection("localhost", "root", "newtha12", "passManager")

    # cursor = connection.cursor()

    # cursor.execute("INSERT INTO users (Service, User, Pass) VALUES (%s, %s, %s)", (service, username, password))

    # connection.commit()

    # return


def get_login(service):
                    #TODO: CREATE ENV VARIABLE
    connection = create_connection("localhost", "root", "Idog9587!", "passManager")

    cursor = connection.cursor()

                            ##TODO: this users table may have to be changed
    cursor.execute("SELECT User, Pass FROM users WHERE Service = (%s)", (service,))

    login = cursor.fetchall()
    #password = decrypt(Pass)

    if(len(login) == 0):
        print('Credentials not found \n')
        #TODO: make sure this doesn't fuck stuff up
        cursor.close()
        connection.close()
        return
    else:
        print('Credentials found: \n')
        cursor.close()
        connection.close()

        return login
    return

    # Creates a new user
    # When do we use? ASSUME FOR NOW BIG OL BUTTON
    #DB DONE
def create_user(master_password, username):

    #SEND SALT TO TABLE WE NEED THIS MF STORED
    salt = os.urandom(16)
    key_encryption_key = generate_master_key(master_password, salt)
    user_table_key = generate_user_table_key(key_encryption_key)

    service_key = generate_service_table_key()
    #using one table for all encrypted master values
    # abby comes in
    # Need to store:
    username = username
    encrypted_user_table_key = key_encryption_key.encrypt(user_table_key)
    encyrpted_KEK = user_table_key.encrypt(key_encryption_key)
    encrypted_validator = user_table_key.encrypt(user_table_key)
    salt = salt
    encrypted_service_key = user_table_key.encrypt(service_key)

    # SEND EVERYTHING TO USER_TABLE
                        #TODO: ADD ENV VARIABLE
     connection = create_connection("localhost", "root", "Idog9587!", "passManager")

     cursor = connection.cursor()

     #TODO: MENTION VARCHAR FOR USERNAME
     #TODO: are these strings or integers?
     cursor.execute("INSERT INTO user_table (username, eutk, eKEK, ev, salt, esk) VALUES (%s, %s, %s, %s, %s)", (username, encrypted_user_table_key, 
            encrypted_KEK, encrypted_validator, salt, encrypted_service_key))

     connection.commit()

     cursor.close()

     connection.close()

    return


    # Creates a master key for a new user, which will be used later
    # Would have liked to use 'username' to seed as well
    #TODO: ASK
def generate_master_key(master_password, salt):
    # master_password - user supplied master password. The pm does not store this, the user must remember it.
    # this is generated only once per user, it needs to be stored in order to regenerate the master key for authentication

    # CONVERT MASTER PASSWORD INTO BYTES ??
    #Password Based Key Derivation, a slow hashing function
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        )
    #derives the key from the password
    master_key = base64.urlsafe_b64encode(kdf.derive(master_password))
    f = Fernet(master_key)
    #RETURN TO ENCRYPT_USER_TABLE TO SEND TO TABLE ?

    return f

    # Generates the key used to encrypt items stored in user_table
def generate_user_table_key(KEK):
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

    # Generates a key used to encrypt items in the service table
def generate_service_table_key():
    key = Fernet.generate_key()
    service_table_key = Fernet(key)
    return service_table_key


    # Checks if user supplied password matches the stored one
    #also has added functionality of decrypting and saving the things we need, 
        # stretch goal is that when app "terminates" the saved things are cleared from mem
    #DB done (I think)
def authenticate_user():   

    # USER ENTERS USERNAME #
    #username = 
    #attempted_pass = USER_ENTERED_MASTER_PASSWORD
    #SALT IS NOT ENCRYPTED WHEN ITS STORED!
              #TODO: ADD ENV VARIABLE
    #grab: salt, encrypted_user_table_key,  grab encrypted validator
     connection = create_connection("localhost", "root", "Idog9587!", "passManager")

     cursor = connection.cursor()

     salt = cursor.execute("SELECT salt FROM user_table WHERE username = (%s)", (username))

     encrypted_user_table_key = cursor.execute("SELECT eutk FROM user_table WHERE username = (%s)", (username))

     encrypted_validator = cursor.execute("SELECT ev FROM user_table WHERE username = (%s)", (username))

     connection.commit()

     cursor.close()

     connection.close()

    #KEK = generate_master_key(attepted_pass, salt)
    #table_key = KEK.decrypt(encrypted_user_table_key)
    #validator = KEKorTABLE_KEY.decrypt(encrypted_validator)

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
    return


def add_service(service, username, password, KEK):
    #generate random key, encrypt password with that key, encrypt key with kek, send to db
    key = Fernet.generate_key()
    f = Fernet(key)
    encrypted_pass = f.encrypt(password)
    KEK = #get KEK
    encrypted_key = #KEK.encrypt(f)
    #what?
    #call function that sends to db, that function will encrypt using service_key

    #for each service we store service, username, encrypted_pass, encrypted_key
    return

def get_service(service, user_table_key, KEK):
    #if service in table service
    #grab value stored in encrypted_pass and encrypted_key
    #KEK = get KEK
    #key = KEK.decrypt(encrypted_key)
    #password = key.decrypt(encrypted_pass)
    return #password




@Gooey(program_name='open-sesame')  # attach Gooey to our code
def main():
    parser = GooeyParser()  # main app
    subs = parser.add_subparsers()  # add functions to the app
    add_parser = subs.add_parser('add')  # add the "add password" function
    get_parser = subs.add_parser('get')  # add the "get password" function

    # add user input fields for function parameters
    add_parser.add_argument('Service', widget='Textarea', gooey_options={
        'initial_value': 'Backrub'
    })
    add_parser.add_argument('Username', widget='Textarea', gooey_options={
        'initial_value': 'elliot_alderson'
    })
    add_parser.add_argument('Password', widget='Textarea', gooey_options={
        'initial_value': 'eXamp!e_102'
    })

    get_parser.add_argument('Service', widget='Textarea', gooey_options={
        'initial_value': 'Backrub'
    })

    args = vars(parser.parse_args())    # initialize app

    # Checkpoint: will need to change to account for add_service and add_user. FIX BELOW
    if len(args) > 1:   # add password
        print('Encrypting password ...')
        ##   NEW USER ALERT!! ##
        ##     ENCRYPTING     ##
        ## HASH PASSWORD HERE ##

        new_pass = bytes(args['Password'], 'utf-8')
        master_key = generate_master_key(new_pass, args['Username'])

        service, username, password = args['Service'], args['Username'], master_key
        add_login(service, username, password)
        print('Credentials stored \n')
    else:   # get password
        service = args['Service']
        print('Searching for {} ...'.format(service))
        creds = get_login(service)
        if creds:
            print('\tService \t\t=>\t {} \n \tUsername \t=>\t {} \n \tPassword \t=>\t {}'.format(
                service, creds[0][0], creds[0][1]))


main()
