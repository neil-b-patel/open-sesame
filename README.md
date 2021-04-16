# open-sesame
Password Manager -- Group Final Project for CSC 382: Introduction to Information Security

## Authors
- Neil Patel '22
- Abby Santiago '22
- Ben Santiago '22

## Usage
1. Clone the GitHub repo @ https://github.com/nepatel/open-sesame.git
2. Install dependencies (Gooey, mysql-connector) using pip3 
3. Run "manager.py" 
4. From the Actions side panel, select...
    - "add" to add a password (required input of service, username, password)
    - "get" to get a password (required input of service)
5. Click...
    - "Start" to perform the action
    - "Cancel" to exit the application
6. If...
    - succesful, click "OK" and view output
    - unsuccesful, raise an GitHub issue detailing your usage and copy the error log
7. To...
    - perform another action, click "Edit"
    - rerun the same action (w/ the same inputs), click "Restart"
    - exit the application, click "Close"

## Technologies
- Gooey (GUI library)
- MySQL (Database)
