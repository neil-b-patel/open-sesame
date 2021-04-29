# open-sesame
Password Manager -- A Group Final Project for CSC 382: Introduction to Information Security

## Authors
- Neil Patel '22
- Abby Santiago '22
- Ben Santiago '22

## Usage
1. Install and configure MySQL Server (at least v8) @ https://dev.mysql.com/downloads/installer/
2. Clone the GitHub repo @ https://github.com/nepatel/open-sesame.git
3. Install any missing dependencies (base64, cryptography, python-dotenv, Gooey, mysql-connector-python, os) using pip3
4. Run "manager.py" 
5. If no .env file is found for a DB connection, prompt the user to generate one
6. From the Actions side panel, select...
    - "setup" to create an account (required input of username, master password)
    - "login" to login into an account previously setup (required input of username, master password)
7. From the Actions side panel, select... [NOTE: These functions will only work if you succesfully login!]
    - "add" to add a password (required input of service, username, password)
    - "get" to get a password (required input of service, username)
    - "update" to update a password (required input of service, username, password)
    - "delete" to delete a password (required input of service, username)
8. Click...
    - "Start" to perform the action
    - "Cancel" to exit the application
9. If...
    - succesful, click "OK" and view output
    - unsuccesful, raise an GitHub issue detailing your usage and copy the error log
10. To...
    - perform another action, click "Edit"
    - exit the application, click "Close"

## Help
- Ensure you have installed "mysql-connector-python" and not the deprecated "mysql-connector" using pip3
- Ensure you have installed and configured MySQL (v8 or later)
- Ensure your MySQL Database's HOST/USER/PASSWD/DB_NAME matches the entries in .env
- Ensure .env is in the same directory as manager.py
- If "add",  "get", "update", or "delete" are not working, ensure you have successfully logged in with "login"
- If this the first time you are using this app, ensure you have successfully an account with "setup"
- The action "update" only lets you change the password for a login. In order to change more, "delete" the old login and "add" a new one.

## Technologies
- Cryptography (Encryption library)
- Gooey (GUI library)
- MySQL (Database)
