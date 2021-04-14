# from cryptography.fernet import Fernet
from gooey import Gooey, GooeyParser

# TODO:
# BEN => hash passwords
# ABBY => store credentials in database (SQL) instead of "dev_db" file
# NEIL => GUI

def add_login(service, username, password):
    print('Storing credentials ...')
    db = open('dev_db', 'a')
    db.write('{} : {} : {}\n'.format(service, username, password))
    db.close()
    return


def get_login(service):
    db = open('dev_db', 'r')

    while True:
        line = db.readline()   # iterate through lines 

        if not line:    # stop at end of file
            break

        creds = line.split(':')    # split line by the delimiter ':'
        creds = [c.strip() for c in creds]  # remove leading and trailing whitespace

        # check for a matching service (not case sensitive)
        if creds[0].lower() == service.lower():
            print('Credentials found: \n')
            return creds

    print('Credentials not found \n')
    db.close()
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
                creds[0], creds[1], creds[2]))


main()
