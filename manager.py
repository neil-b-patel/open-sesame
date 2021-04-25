from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from gooey import Gooey, GooeyParser
import mysql.connector
import os
import base64
from mysql.connector import Error


# TODO:
# BEN => hash passwords
# ABBY => store credentials in database (SQL) instead of "dev_db" file (done) database-end master password, secure way to deploy/host database
# NEIL => GUI (done) application-end master password, add functionality for changing existing passwords

# does sql create a vulnerability? Do we have to parse it or whatever its called? does the database get hosted locally?
# depending on how db is hosted,
# everything in the database will be encrypted. Service, User/email, and Password and #more things to come!
# How do you imagine the fully functional version working? When users open the pm they have to enter their masterPass
# If correct (more detail below), they will be able to add new services/passwords and get passwords from existing services
# If adding, do_proper_encryption and send to db
# If getting, do_proper_decryption of things in db
# Q: Will the user supply/input the service they want, or will they be able to choose among the options?
# I believe it'd be more secure if they have to supply. The process of accessing and decrypting things from the db will look different depending
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


    # We need add_login and add_service to be two seperate functions i think
def add_login(service, username, password):
    # Throws error when adding a repeat service/username. We probably need something to handle changing a password for existing service
    print('Storing credentials ...')
                                                        #this is not a secure thing to be doing ...right
    connection = create_connection("localhost", "root", "newtha12", "passManager")

    cursor = connection.cursor()
                                                      #Pass is encrypted at this point
    cursor.execute("INSERT INTO users (Service, User, Pass) VALUES (%s, %s, %s)", (service, username, password))

    connection.commit()

    return


def get_login(service):

    connection = create_connection("localhost", "root", "Idog9587!", "passManager")

    cursor = connection.cursor()
                                #pass will be super encrypted
    cursor.execute("SELECT User, Pass FROM users WHERE Service = (%s)", (service,))

    login = cursor.fetchall()
    #password = decrypt(Pass)

    if(len(login) == 0):
        print('Credentials not found \n')
        return
    else:
        print('Credentials found: \n')
        return login
    return

    # Creates a new user. So right now 'user' is just a variable that we send to a database, I think this has to be a lil beefier.
    # For instance, a UI where user enters username and master password. This is where we authenticate the user.
    # Once user enters name and password they can 'add or update password' or 'get_password'
def create_user():

    # username = username
    # salt = salt
    # make secret key
    # make master key
    # make database key
    # make service database key
    return


    # Creates a unique user key, which will be used later
def create_user_key():
    # Idk how complicated to get with this secret key generation, we got options
    # could be as simple as appropriately generated random value
    return


    # Creates a master key for a new user, which will be used later
def generate_master_key(master_password, username):
    # master_password - user supplied master password. The pm does not store this, the user must remember it.
    # this is generated only once per user, it needs to be stored in order to regenerate the master key for authentication

        salt = os.urandom(16)
    #generate salt for key generation
    #the salt has to be stored in a retrievable location in order to derive same key in future


    #slow hash function
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            )

    #generate key from hash generated above, as long as we know salt we can re-compute for authentication
        key = base64.urlsafe_b64encode(kdf.derive(new_pass))
    # ^ might use master_key up here, wont need to  store salt for master_key just the key generated from it
    #to generate secure new_pass, use master_key as the seed for below
        f = Fernet(key)
    #I am not sure exactly what I'm doing up here ^, I think this might be what we do for the master_pass
        token = f.encrypt(new_pass)
        print(token)
        print(f.decrypt(token))

        return token

    # Is authentication the proper technical term?
    # Checks if user supplied password matches the stored one
def authenticate_user():
    # (We are checking the keys not the passwords)
    # access database and get the key that is stored there (database will be encryoted! with what? idk yet :/ )
    # do we store the master key in plaintext?

    #Authentication on master Password:
    #Read encryptedDatabaseKey and encryptedValidator from db
    #KEK = MD5(master_password + salt)
    #IV = MD5(KEK + password + salt)
    #DatabaseKey = AES-CBC (KEK, IV, encryptedDatabaseKey)
    #Validator = AES-CBC (DatabaseKey, NULL, encryptedValidator)
    #If validator = DatabaseKey then password is correct

    #store an encrypted version of the master key
    #when user logs into Open Sesame they will enter their master pass
    return

    # Encrypts things stored in service database
def encrypt_service():
    # What is going to be stored? How will it be encrypted?
    return


    # Encrypts things stored in user database
def encrypt_user():
    # What is going to be stored? How will it be encrypted?
    return

    # Decrypts things stored in service database
def decrypt_service():
    ####
    # arguments:
    # encryptedPass:
    # ###
    return


    # Decrypts things stored in user dayabase
def decrypt__user():
    # User database will store: master_key(used to generate all types of keys, more detail tbd),
    # secret_key(used to generate master_key and also maybe other password? tbd),
    # database_key(used to encrypt things in the database),
    # service_database_key(not thought out, the key used to encrypt service database)
    # username, I guess
    # Oh also the salt used to generate the master key, I think?
    return


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
        ## When and where do we set the masterPassword?
        ## Plan on doing:
        ##      Use masterpassword to create a master key, master_key = robust_cryptology_function(masterPass, salt, (optional?) MAC)
        ##      when user creates a new pass word for a new service (or new password for old service) we encrypt that new_pass
        ##      new_pass is generated with  new_encrytption_key, new_encryption_key is generated using master_key
        ##      new_encryption_key is used to encrypt contents of new_pass
        ##      new_pass is saved...where? I guess right now just pass send it straight to the MySQL database
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
