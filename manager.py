from cryptography.fernet import Fernet

# TODO:
# hash passwords
# store hashed password in database (SQL) [instead of a python dict]
# API to authenticate user and retrieve stored logins
# temp data storage (service: (password, username))

logins = {}

def generate_key(master_pass):
	# key = Fernet.generate_key()
	# with open(master_pass, "wb") as f:
	# 	f.write(key)
	# return key
    pass

def get_key(master_pass):
	# key = open(master_pass, "rb").read()
	# return key
    pass

def addLogin(service, username, password, secret):
    print('Storing credentials ...')
    # hashes = (sha256(username.encode()), sha256(password.encode()))
    creds = (username, encrypt_block(password, secret))
    print(creds)
    logins[service] = creds
    return

def getLogin(service):
    # check if login for service exists
    print(logins)
    if service in logins:
        print('Retrieving credentials ...')
        return logins[service]
    else:
        print('Error: Credentials for {} not found'.format(service))
        return

def main():
    # authenticated = False
    done = False

    # while not authenticated:
    #     cmd = input('C(reate Account)\nL(ogin to Account)\n')
    #     if cmd == 'C' or cmd == 'c':
    #         master_pass = input('Enter a master password: \n')
    #         key = generate_key(master_pass)
    #         authenticated = True
    #     elif cmd == 'L' or cmd == 'l':
    #         master_pass = input('Enter your master password: \n')
    #         key = get_key(master_pass)
    #         authenticated = True
    #     else:
    #         print('G00D BY3 :)\n')
    #         return
            
    # if secret == key:
    #     print('Welcome back.\n')
    # else:
    #     print('Nice one! try again :p\n')
    #     return
    
    while not done:
        cmd = input('What would you like to do? \nA(dd) a login \nG(et) a login \n')
        print()
        if cmd == 'A' or cmd == 'a':
            service = input('Enter the service name:\n')
            username = input('Enter the username for the service:\n')
            password = input('Enter the password for the service:\n')
            addLogin(service, username, password, secret)
            print(logins)
        elif cmd == 'G' or cmd == 'g':
            service = input('Enter the service name:\n')
            creds = getLogin(service)
            print(creds)
        else:
            print('G00D BY3 :)\n')
            done = True
    return

main()
