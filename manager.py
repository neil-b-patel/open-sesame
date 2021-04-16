# from cryptography.fernet import Fernet
from gooey import Gooey, GooeyParser
import mysql.connector
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

    connection = create_connection("localhost", "root", "Idog9587!", "passManager")

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
        ##     ENCRYPTING     ##
        ## HASH PASSWORD HERE ##
        service, username, password = args['Service'], args['Username'], args['Password']
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
