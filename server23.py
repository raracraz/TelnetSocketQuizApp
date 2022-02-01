
import base64
import socket, threading
import DBcom
import glob, os
import re

# Global variable that mantain client's connections
connections = []
file = ''
main_menu = '\n\n+==================================+\n      Welcome to The Quiz\n ________  ___  ___  ___   ________\n| \  __  \|\  \|\  \|\  \ |\_____  \ \n \ \ \ |\ \ \  \\ \\  \ \  \ \|___/  /|\n  \ \ \ \\\ \ \  \\ \\  \ \  \    /  / / \n   \ \ \_\\\ \ \  \\_\\  \ \  \  /  /_/__\n    \ \_____ \ \_______\ \__\ |\_______\ \n     \|___|\__\|_______|\|__| \|_______|\n          \|__|\n+==================================+\n1. Login\n2. Register\n3. Forget password\n\n<ENTER> to Exit\nPlease select your choice: '
# Update the database data with the new message

def handle_user_connection(connection: socket.socket, address: str) -> None:
    '''
        Get user connection in order to keep receiving their messages and
        sent to others users/connections.
    '''
    def menu() -> str:   
        connection.send(bytes(, encoding='ascii'))
        try:
            UserRequest = connection.recv(1024).decode()
            UserRequest = int(UserRequest)
            if UserRequest == 1:
                UserRequest = 'LOGIN'

            elif UserRequest == 2:
                UserRequest = 'REGISTER'

            elif UserRequest == 3:
                UserRequest = 'FORGETPASSWORD'

            else:
                menu()
            # if the user enters a non-integer (eg: spacebar) then program exits.
        except ValueError:
            connection.send(bytes('Goodbye...'))
            remove_connection(connection)
            
        return UserRequest

    def login() -> str:
        '''
        Login user
        '''
        connection.send(bytes('+==================================+\n\t     Login Menu\n+==================================+\n\nUsername: ', encoding='utf-8'))
        
        # Get user name
        username = connection.recv(1024)
        username = username.decode('utf-8')
        print(username)

        # Get user password
        connection.send(bytes('Password: ', encoding='utf-8'))
        password = connection.recv(1024)
        password = password.decode('utf-8')
        print(password)

        # bool values
        username_pass = False
        password_pass = False
        
        # Check if user exists on database
        rowid = DBcom.UserDB.find('users', 'username', 'data','', 'id', username)
        username_pass = DBcom.UserDB.find('users', 'username', 'data','','bool', username)
        password_pass = DBcom.UserDB.find('users', 'password', 'data','','bool', password)
        localrowid = rowid
        try:
            #checks if the account has the nessesary permissions to login
            #acl = '00000' means no permissions to login admin menu
            #acl = '11111' means all permissions to login admin menu            
            #if the username and password are valid and exist then the user is logged in.
            #the logged in session will have a unique id according to the user logged in.
            if len(username_pass) > 0 and len(password_pass) > 0 and localrowid != '':
                msg_to_send = str(localrowid).encode()
                print('logged in')
                #doUserQuestions(str(localrowid)) #go to the app
            else:
                msg_to_send = 'False'
                
        except ValueError:
                msg_to_send = 'False'

        except IndexError:
                msg_to_send = 'False'

        if msg_to_send == 'False':
            connection.send(('Incorrect username or password\n').encode())
            login()
        return msg_to_send

    def generateOTP():
            #get a random number then hash it to 8 digits
            randomNumber = os.urandom(16)
            randomNumber = abs(hash(randomNumber) % (10 ** 8))
            return randomNumber

    def register() -> str:
        '''
        Register a new user on the database
        '''
        CoursesList = []
        Attempts = DBcom.UserDB.find('questions', 'NumberOfAtt', 'id', 're','raw','')
        Attempts = Attempts[0].split('_')[2]
        localrowid = str(abs(hash(os.urandom(16)) % (10 ** 8)))
        Courses = DBcom.UserDB.find('users', 'AllCourses', 'id', 're','raw','')
        for i in range(len(Courses)):
            print('{}. {}'.format(i+1, base64.b64decode(Courses[i].split('_')[2]).decode('utf-8')))
            CoursesList.append(str(i+1) + '. ' + base64.b64decode(Courses[i].split('_')[2]).decode('utf-8'))

        CoursesList = str(CoursesList).replace("'", "").replace("[", "").replace("]", "").replace(" ", "").replace(",", "\n")
        connection.send(bytes('+==================================+\n\t    Register User\n+==================================+\n\nCourses:\n{}\n\n<Enter> to go back\nPlease enter your Course:'.format(CoursesList), encoding='utf-8'))
        course = connection.recv(1024).decode()
        try:
            course = int(course)
            if course > len(Courses) or course < 1:
                connection.send(bytes('Invalid Course\n', encoding='utf-8'))
                register()
            else:
                course = Courses[course-1].split('_')[2]
        except ValueError:
            connection.send(bytes('Invalid Course\n', encoding='utf-8'))
            register()
        connection.send('+==================================+\n\t    Register User\n+==================================+\nRequirements:\n1. Username must not contain special characters\n2. Username/Password must be [4-20] characters\n3. Password must contain at least one special character [@#$%^&+=]\n4. Password must contain at least one upper and lower case letter\n5. Password must contain at least one number [0-9]\n5. Password must contain at least one number [0-9]\n<b> to back\n+==================================+\nPlease enter your Username:'.encode())
        #Username Requirements
        regUser = "^[a-zA-Z0-9]{4,20}$"
        patUser = re.compile(regUser)
        #Password Requirements
        regPass = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{4,20}$"
        patPass = re.compile(regPass)
        #Check if username is valid
        try:
            username = connection.recv(1024).decode()
        except ValueError:
            connection.send(bytes('Invalid Username\n', encoding='utf-8'))
            register()
        if username == 'b':
            menu()
        mat = re.search(patUser, username)
        if mat:
            pass
        else:
            connection.send(bytes('Username is not valid\n', encoding='utf-8'))
            register()
        if username == '':
            menu()

        connection.send(bytes('Please enter your Password:', encoding='utf-8'))
        password = connection.recv(1024).decode()
        mat = re.search(patPass, password)
        if mat:
            pass
        else:
            connection.send(bytes('Password is not valid\n', encoding='utf-8'))
            register()
        connection.send(bytes('Please confirm your password: ', encoding='utf-8'))
        password_confirm = connection.recv(1024).decode()
        if password == password_confirm:
            pass
        else:
            print(colors.fg.red,'Password does not match', colors.reset)
            register()
        # ask for email
        connection.send(bytes('Please enter your email: ', encoding='utf-8'))
        email = connection.recv(1024).decode()
        otp = str(generateOTP())

        #check if username is already taken
        if len(DBcom.UserDB.find('users', 'username', 'data','' , 'bool', username)) > 0:
            connection.send(bytes('Username is already taken\n', encoding='utf-8'))
            register()
        else:
            username_pass = True

        #check if email is a valid email
        if re.match(r"[^@]+@[^@]+\.[^@]+", email) == None:
            connection.send(bytes('Email is not valid\n', encoding='utf-8'))
            email_pass = False
            register()
        else:
            email_pass = True

        if len(DBcom.UserDB.find('users', 'email', 'data','' ,'bool', email)) > 0:
            connection.send(bytes('Email is already taken\n', encoding='utf-8'))
            email_pass = False
            register()
        else:
            email_pass = True

        #if all requirements are met then the user account is created with admin permissions.
        if username_pass == True and email_pass == True:
            try:
                #get the current number of attempts
                DBcom.UserDB.create('users', 'acl', 's', localrowid, '00000')
                DBcom.UserDB.create('users', 'username', 's', localrowid, username)
                DBcom.UserDB.create('users', 'password', 's', localrowid, password)
                DBcom.UserDB.create('users', 'otp', 's', localrowid, str(otp))
                DBcom.UserDB.create('users', 'email', 's', localrowid, email)
                DBcom.UserDB.create('users', 'AttemptNo', 's', localrowid, str(Attempts))
                DBcom.UserDB.create('users', 'UserCourses', 's', localrowid, course)
                
                print('+==================================+')
                print('Registration successful,\nreturn to the menu to login!\n')
                print('your email is {}, recovery OTP is {}'.format(email,otp))
                print('+==================================+\n')
                
                menu()
            except ValueError:
                connection.send(bytes('Error creating user\n', encoding='utf-8'))
                register()
        else:
            register()

    while True:
        try:
            # print menu for the user to choose what to do
            msg = menu()
            # Get client message
            
            # If no message is received, there is a chance that connection has ended
            # so in this case, we need to close connection and remove it from connections list.
            if msg:
                try:
                    msg_decoded = msg
                    # Log message sent by user
                    if str.isascii(msg_decoded):
                        print(f'{address[0]}:{address[1]} - {msg_decoded}')
                        # Build message format and broadcast to users connected on server
                        # msg_to_send = f'From {address[0]}:{address[1]} - {msg_decoded}'
                        # broadcast(msg_to_send, connection)
                        
                        if msg_decoded == 'LOGIN':
                            localrowid = login()
                        
                        elif msg_decoded == 'REGISTER':
                            register()

                    else:
                        pass
                except UnicodeDecodeError:
                    print('skipping non-ascii message')
                    pass

            # Close connection if no message was sent
            #else:
            #    remove_connection(connection)
            #    break
            

        except Exception as e:
            print(f'Error to handle user connection: {e}')
            remove_connection(connection)
            break
def broadcast(message: str, connection: socket.socket) -> None:
    '''
        Broadcast message to all users connected to the server
    '''

    # Iterate on connections in order to send message to all client's connected
    for client_conn in connections:
        # Check if isn't the connection of who's send
        if client_conn != connection:
            try:
                # Sending message to client connection
                client_conn.send(message.encode())

            # if it fails, there is a chance of socket has died
            except Exception as e:
                print('Error broadcasting message: {}'.format(e))
                remove_connection(client_conn)


def remove_connection(conn: socket.socket) -> None:
    '''
        Remove specified connection from connections list
    '''

    # Check if connection exists on connections list
    if conn in connections:
        print(f'Removing connection: {conn}')
        # Close socket connection and remove connection from connections list
        conn.close()
        connections.remove(conn)


def server() -> None:
    '''
        Main process that receive client's connections and start a new thread
        to handle their messages
    '''

    LISTENING_PORT = 23
    
    try:
        # Create server and specifying that it can only handle 4 connections by time!
        socket_instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_instance.bind(('', LISTENING_PORT))
        socket_instance.listen(4)

        print('Server running!')
        
        while True:

            # Accept client connection
            socket_connection, address = socket_instance.accept()
            # Add client connection to connections list
            connections.append(socket_connection)
            # Start a new thread to handle client connection and receive it's messages
            # in order to send to others connections
            print('got a connection')
            threading.Thread(target=handle_user_connection, args=[socket_connection, address]).start()

    except Exception as e:
        print(f'An error has occurred when instancing socket: {e}')
    finally:
        # In case of any problem we clean all connections and close the server connection
        if len(connections) > 0:
            for conn in connections:
                remove_connection(conn)

        print('Closing server...')
        socket_instance.close()



if __name__ == "__main__":
    server()

# color for terminal
class colors:
	reset='\033[0m'
	bold='\033[01m'
	disable='\033[02m'
	underline='\033[04m'
	reverse='\033[07m'
	strikethrough='\033[09m'
	invisible='\033[08m'
	class fg:
		black='\033[30m'
		red='\033[31m'
		green='\033[32m'
		orange='\033[33m'
		blue='\033[34m'
		purple='\033[35m'
		cyan='\033[36m'
		lightgrey='\033[37m'
		darkgrey='\033[90m'
		lightred='\033[91m'
		lightgreen='\033[92m'
		yellow='\033[93m'
		lightblue='\033[94m'
		pink='\033[95m'
		lightcyan='\033[96m'
	class bg:
		black='\033[40m'
		red='\033[41m'
		green='\033[42m'
		orange='\033[43m'
		blue='\033[44m'
		purple='\033[45m'
		cyan='\033[46m'
		lightgrey='\033[47m'