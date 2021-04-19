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
# ABBY => store credentials in database (SQL) instead of "dev_db" file (done)
# NEIL => GUI (done)


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



def add_login(service, username, password):

    print('Storing credentials ...')

    connection = create_connection("localhost", "root", "newtha12", "passManager")

    cursor = connection.cursor()

    cursor.execute("INSERT INTO users (Service, User, Pass) VALUES (%s, %s, %s)", (service, username, password))

    connection.commit()

    return


def get_login(service):

    connection = create_connection("localhost", "root", "Idog9587!", "passManager")

    cursor = connection.cursor()

    cursor.execute("SELECT User, Pass FROM users WHERE Service = (%s)", (service,))

    login = cursor.fetchall()

    if(len(login) == 0):
        print('Credentials not found \n')
        return
    else:
        print('Credentials found: \n')
        return login
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

        #convert password to bytes because...
        new_pass = bytes(args['Password'], 'utf-8')

        #generate salt for key generation
        #the salt has to be stored in a retrievable location in order to derive same key in future
        salt = os.urandom(16)

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

        service, username, password = args['Service'], args['Username'], token
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
