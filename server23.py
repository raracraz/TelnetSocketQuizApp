
import base64
import socket
import sys
import threading

import DBcom
import glob
import os
import re
import json


# Global variable that mantain client's connections
connections = []
# Variables for the different types of messages\menu
startMenu = '\n\nYou are Connected to the server, welcome to the Quiz App!\n\n\nEnter any Key to Start...\nEnter <exit> to exit ' 
mainMenu = '\n\n+==================================+\n      Welcome to The Quiz\n ________  ___  ___  ___   ________\n| \  __  |\  \|\  \|\  \ |\_____  \ \n \ \ \ |\ \ \  \\ \\  \ \  \ \|___/  /|\n  \ \ \ \\\ \ \  \\ \\  \ \  \    /  / / \n   \ \ \_\\\ \ \  \\_\\  \ \  \  /  /_/__\n    \ \_____ \ \_______\ \__\ |\_______\ \n     \|___|\__\|_______|\|__| \|_______|\n          \|__|\n+==================================+\n1. Login\n2. Register\n3. Forget password\n\n<ENTER> to Exit\nPlease select your choice: '
loginMenu = '+==================================+\n\t     Login Menu\n+==================================+\n\nUsername: '
forgetPasswordMenu = '+==================================+\n\tForget Password Menu\n+==================================+\n\n<ENTER> to back\nPlease enter your email: '
registerRequirements = '+==================================+\n\t    Register User\n+==================================+\nRequirements:\n1. Username must not contain special characters\n2. Username/Password must be [4-20] characters\n3. Password must contain at least one special character [@#$%^&+=]\n4. Password must contain at least one upper and lower case letter\n5. Password must contain at least one number [0-9]\n5. Password must contain at least one number [0-9]\n<b> to back\n+==================================+\nPlease enter your Username:'
# Update the database data with the new messaged

#############################################################################
#                               functions                                   #
#############################################################################

def formatParser(theType,theMessage,thePrompt='>', menuid = 0, minLength=1,maxLength=512,minVal=1,maxVal=99,mask='*'):
    jsonStr = {'type': theType, 'message': theMessage, 'prompt': thePrompt, 'minLength': minLength, 'maxLength': maxLength, 'minVal': minVal, 'maxVal': maxVal, 'mask': mask, 'menuid': menuid}
    return json.dumps(jsonStr)

def receiveParser(data):
    try:
        jsonStr = json.loads(data)
        return jsonStr
    except:
        print('Error: data is not in JSON format')
        return False



def handleUserConnection(connection: socket.socket, address: str) -> None:
    '''
        Get user connection in order to keep receiving their messages and
        sent to others users/connections.
    '''
    
    def menu(menuid, theMessage) -> str:
        
        userlogin = False
        userRegister = False
        forgetPass = False
        menuState = 0

        if menuid == 0:
            connection.send(formatParser('text',mainMenu,'>', 0).encode())

        elif menuid == 1: ##LOGIN
            connection.send(formatParser('text',loginMenu,'>', 0).encode())
            menuState += 1

        elif menuid == 1 and menuState == 1:
            username = theMessage
            connection.send(formatParser('text','Username: ','>', 1).encode())
            menuState += 1

        elif menuid == 1 and menuState == 2:
            password = theMessage
            connection.send(formatParser('text','Password: ','>', 1).encode())
            menuState += 1

        elif userlogin == False:
            connection.send(formatParser('text','Invalid username or password','>', 0).encode())
            menuState = 0
            menuid = 0

        elif menuid == 2: ##REGISTER
            courseChoice = theMessage
            connection.send(formatParser('text','+==================================+\n\t    Register User\n+==================================+\nCourses:\n\n{}. {}\n<Enter to back\nPlease enter your Course: >'.format('1', 'Courses'),'>', 0).encode())
            menuState += 1

        elif menuid == 2 and menuState == 1:
            username = theMessage
            connection.send(formatParser('text',registerRequirements,'>', 2).encode())
            menuState += 1

        elif menuid == 2 and menuState == 2:
            password = theMessage
            connection.send(formatParser('text','Password: ','>', 2).encode())
            menuState += 1

        elif menuid == 2 and menuState == 3:
            confirmPass = theMessage
            connection.send(formatParser('text','Confirm Password: ','>', 0).encode())
            menuState += 1

        elif menuid == 2 and menuState == 4:
            email = theMessage
            connection.send(formatParser('text','Email: ','>', 0).encode())
            menuState += 1

        elif userRegister == False:
            connection.send(formatParser('text','Invalid username or password','>', 0).encode())
            menuState = 0
            menuid = 0

        elif menuid == 3: ##FORGET PASSWORD
            connection.send(formatParser('text',forgetPasswordMenu,'>', 0).encode())
            menuState += 1

        elif forgetPass == False:
            connection.send(formatParser('text','Invalid email','>', 0).encode())
            menuState = 0
            menuid = 0

        elif menuid == 4: ##doUserMenu
            connection.send((formatParser('text','+==================================+\n\tUser Question Menu...\nUserID: {}\n+==================================+\n\n1. Take Quiz\n2. User results\n\n<ENTER> to go back to login page\n(You will be logged out)\n+==================================+\n\nPlease enter your choice:').format('username'), '>', 4+int(theMessage)).encode())

        elif menuid == 5: ##Quiz
            connection.send(formatParser('text', '+==================================+\n             Take Quiz\n+==================================+\n\nDo you want to take a quiz?\n1. Yes\n2. No\n\n<ENTER> to go Back\nPlease enter your choice: ','>', 0).encode())
            menuState += 1

        elif menuid == 5 and menuState == 1:
            # MAIN QUIZ LOOP
            pass

        elif menuid == 6: ##View Results
            connection.send((formatParser('text', '+==================================+\n             View Results\n+==================================+\nResults: \n\n{}. {}\n\n<ENTER> to go Back\nPlease enter your choice: ').format('i', 'results'),'>', 0).encode())
            menuState += 1

        elif menuid == 6 and menuState == 1:
            connection.send((formatParser('text', '+==================================+\n           User Results\n+==================================+\nQuestions: \n\n{}. {}\n\n+==================================+\n           User Results\n+==================================+').format('i', 'results'),'>', 0).encode())
            menuid = 4




        else:
            connection.send(formatParser('text', mainMenu,'>', 0).encode())


    def login() -> str:
        '''
        Login user
        '''
        connection.send(formatParser('text',loginMenu,'>').encode())

        # Get user name
        username = connection.recv(1024).decode()
        if username == '99':
            menu()
        print(username)

        # Get user password
        connection.send(formatParser('text','Password: ','>').encode())
        password = connection.recv(1024).decode()
        print(password)

        # bool values
        username_pass = False
        password_pass = False

        # Check if user exists on database
        rowid = DBcom.UserDB.find(
            'users', 'username', 'data', '', 'id', username)
        username_pass = DBcom.UserDB.find(
            'users', 'username', 'data', '', 'bool', username)
        password_pass = DBcom.UserDB.find(
            'users', 'password', 'data', '', 'bool', password)
        localrowid = rowid
        try:
            # checks if the account has the nessesary permissions to login
            # acl = '00000' means no permissions to login admin menu
            # acl = '11111' means all permissions to login admin menu
            # if the username and password are valid and exist then the user is logged in.
            # the logged in session will have a unique id according to the user logged in.
            if len(username_pass) > 0 and len(password_pass) > 0 and localrowid != '':
                msg_to_send = str(localrowid).encode()
                currMenu = '1.' + '1.'
                # doUserQuestions(str(localrowid)) #go to the app
            else:
                msg_to_send = 'False'

        except ValueError:
            msg_to_send = 'False'

        except IndexError:
            msg_to_send = 'False'

        if msg_to_send == 'False':
            connection.send(formatParser('text','Incorrect username or password\n','>').encode())

        return currMenu

    def register() -> str:
        '''
        Register a new user on the database
        '''
        def generateOTP():
            # get a random number then hash it to 8 digits
            randomNumber = os.urandom(16)
            randomNumber = abs(hash(randomNumber) % (10 ** 8))
            return randomNumber
        CoursesList = []
        Attempts = DBcom.UserDB.find('questions', 'NumberOfAtt', 'id', 're', 'raw', '')
        Attempts = Attempts[0].split('_')[2]

        localrowid = str(abs(hash(os.urandom(16)) % (10 ** 8)))
        Courses = DBcom.UserDB.find('users', 'AllCourses', 'id', 're', 'raw', '')
        for i in range(len(Courses)):
            print('{}. {}'.format(i+1, base64.b64decode(Courses[i].split('_')[2]).decode('utf-8')))
            CoursesList.append(str(i+1) + '. ' + base64.b64decode(Courses[i].split('_')[2]).decode('utf-8'))

        CoursesList = str(CoursesList).replace("'", "").replace("[", "").replace("]", "").replace(" ", "").replace(",", "\n")

        connection.send(formatParser('text', '+==================================+\n\t    Register User\n+==================================+\n\nCourses:\n{}\n\n<Enter> to go back\nPlease enter your Course:'.format(CoursesList), '>').encode())
        course = connection.recv(1024).decode()
        try:
            course = int(course)
            if course > len(Courses) or course < 1:
                connection.send(formatParser('text', '\nInvalid Course\nPress <Enter> to continue...'.format(CoursesList), '>').encode())
                menu()
            else:
                course = Courses[course-1].split('_')[2]
        except ValueError:
            connection.send(formatParser('text', '\nInvalid Course\nPress <Enter> to continue...'.format(CoursesList), '>').encode())
            menu()
        connection.send(formatParser('text', registerRequirements, '>').encode())
        # Username Requirements
        regUser = "^[a-zA-Z0-9]{4,20}$"
        patUser = re.compile(regUser)
        # Password Requirements
        regPass = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{4,20}$"
        patPass = re.compile(regPass)
        # Check if username is valid
        try:
            username = connection.recv(1024).decode()
        except ValueError:
            connection.send(formatParser('text', 'Username is not valid\nPress <Enter> to continue...', '>').encode())
            register()
        if username == 'b':
            menu()
        mat = re.search(patUser, username)
        if mat:
            pass
        else:
            connection.send(formatParser('text', 'Username is not valid\nPress <Enter> to continue...', '>').encode())
            register()
        if username == '':
            menu()

        connection.send(formatParser('text', 'Please enter your password: ', '>').encode())
        password = connection.recv(1024).decode()
        mat = re.search(patPass, password)
        if mat:
            pass
        else:
            connection.send(formatParser('text', 'Password is not valid\nPress <Enter> to continue...', '>').encode())
            register()
        connection.send(formatParser('text', 'Please confirm your Password: ', '>').encode())
        password_confirm = connection.recv(1024).decode()
        if password == password_confirm:
            pass
        else:
            connection.send(formatParser('text', 'Passwords do not match\nPress <Enter> to continue...', '>').encode())
            register()
        # ask for email
        connection.send(formatParser('text', 'Please enter your email: ', '>').encode())
        email = connection.recv(1024).decode()
        otp = str(generateOTP())

        # check if username is already taken
        if len(DBcom.UserDB.find('users', 'username', 'data', '', 'bool', username)) > 0:
            connection.send(formatParser('text', 'Username is already taken\nPress <Enter> to continue...', '>').encode())
            register()
        else:
            username_pass = True

        # check if email is a valid email
        if re.match(r"[^@]+@[^@]+\.[^@]+", email) == None:
            connection.send(formatParser('text', 'Email is not valid\nPress <Enter> to continue...', '>').encode())
            email_pass = False
            register()
        else:
            email_pass = True

        if len(DBcom.UserDB.find('users', 'email', 'data', '', 'bool', email)) > 0:
            connection.send(formatParser('text', 'Password is already taken\nPress <Enter> to continue...', '>').encode())
            email_pass = False
            register()
        else:
            email_pass = True

        # if all requirements are met then the user account is created with admin permissions.
        if username_pass == True and email_pass == True:
            try:
                # get the current number of attempts
                DBcom.UserDB.create('users', 'acl', 's', localrowid, '00000')
                DBcom.UserDB.create('users', 'username', 's', localrowid, username)
                DBcom.UserDB.create('users', 'password', 's', localrowid, password)
                DBcom.UserDB.create('users', 'otp', 's', localrowid, str(otp))
                DBcom.UserDB.create('users', 'email', 's', localrowid, email)
                DBcom.UserDB.create('users', 'AttemptNo', 's', localrowid, str(Attempts))
                DBcom.UserDB.create('users', 'UserCourses', 's', localrowid, course)

                connection.send(formatParser('text','+==================================+\nRegistration successful,\nreturn to the menu to login!\n\nyour email is {}, recovery OTP is {}\n+==================================+\nPress <Enter> to continue...'.format(email, otp),'>').encode())
                currMenu = '2.'
                menu()
            except ValueError:
                connection.send(formatParser('text','Error creating User','>').encode())
                register()
        else:
            register()

    def forgetPassword(): 
        connection.send(formatParser('text', forgetPasswordMenu, '>').encode())
        email = connection.recv(1024).decode()
        if email == '':
            menu()
        if re.match(r"[^@]+@[^@]+\.[^@]+", email) == None:
            connection.send(formatParser('text', '\nEmail is not valid\nPress <Enter> to continue...', '>').encode())
            menu()
        else:
            try:
                localrowid = DBcom.UserDB.find('users', 'email', 'data','', 'id', email)[0]
            except IndexError:
                connection.send(formatParser('text', '\nEmail not found\nPress <Enter> to continue...', '>').encode())
                menu()
            if len(localrowid) != '':
                try:
                    #password = str(base64.b64decode(DBcom.UserDB.find('users', 'password', 'id','raw', localrowid[0])[0].split('_')[2]))[1:]
                    password = str(DBcom.UserDB.find('users', 'password', 'id','','raw', localrowid)).split('_')[2][0:-2]
                    connection.send(formatParser('text', '+==================================+\nWe have sent the password {} to your Email {}\n+==================================+\nPress <Enter> to Continue...\n'.format(password,email), '>').encode())
                    menu()
                except:
                    forgetPassword()
            else:
                print('Email not found')
                forgetPassword()


    # upon first connection we send the user the menu
    
    connection.send(formatParser('text', startMenu, '>', 0).encode())

    while True:
        try:
            # print menu for the user to choose what to do\
            # Get client message
            msg = connection.recv(1024).decode()

            # If no message is received, there is a chance that connection has ended
            # so in this case, we need to close connection and remove it from connections list.
            if msg:
                try:
                    # Log message sent by user
                    if str.isascii(msg):
                        print(f'{address[0]}:{address[1]} - {msg}')

                        jsonData = receiveParser(msg)
                        menuid = jsonData['menuid']
                        theMessage = jsonData['message']
                        if theMessage == '99':
                            menuid -= 1

                                
                        userlogin = False
                        userRegister = False
                        forgetPass = False
                        menuState = 0

                        if menuid == 0:
                            connection.send(formatParser('text',mainMenu,'>', 0).encode())

                        elif menuid == 1: ##LOGIN
                            connection.send(formatParser('text',loginMenu,'>', 1).encode())
                            menuState += 1

                        elif menuid == 1 and menuState == 1:
                            username = theMessage
                            username = ""
                            username_pass = False
                            if username == '99':
                                menuid -= 1
                                menuState = 0
                                break

                            rowid = DBcom.UserDB.find('users', 'username', 'data','', 'id', username)
                            username_pass = DBcom.UserDB.find('users', 'username', 'data','','bool', username)
                            connection.send(formatParser('text','Username: ','>', 1).encode())
                            menuState += 1

                        elif menuid == 1 and menuState == 2:
                            password = theMessage
                            password_pass = DBcom.UserDB.find('users', 'password', 'data','','bool', password)
                            localrowid = rowid
                            try:
            
                                if len(username_pass) > 0 and len(password_pass) > 0 and localrowid != '':
                                    menuState = 0
                                    menuid = 4
                                else :
                                    ('a. Incorrect username or password')
                                    login(localrowid)
                            except ValueError:
                                print(colors.fg.red, 'b. Incorrect username or password', colors.reset)
                                login(localrowid)
                            except IndexError:
                                print(colors.fg.red, 'c. Incorrect username or password', colors.reset)
                                login(localrowid)
                            connection.send(formatParser('text','Password: ','>', 1).encode())
                            menuState += 1

                        elif userlogin == False:
                            connection.send(formatParser('text','Invalid username or password','>', 0).encode())
                            menuState = 0
                            menuid = 0
                        
                    

                        elif menuid == 2: ##REGISTER
                            courseChoice = theMessage
                            connection.send(formatParser('text','+==================================+\n\t    Register User\n+==================================+\nCourses:\n\n{}. {}\n<Enter to back\nPlease enter your Course: >'.format('1', 'Courses'),'>', 0).encode())
                            menuState += 1

                        elif menuid == 2 and menuState == 1:
                            username = theMessage
                            connection.send(formatParser('text',registerRequirements,'>', 2).encode())
                            menuState += 1

                        elif menuid == 2 and menuState == 2:
                            password = theMessage
                            connection.send(formatParser('text','Password: ','>', 2).encode())
                            menuState += 1

                        elif menuid == 2 and menuState == 3:
                            confirmPass = theMessage
                            connection.send(formatParser('text','Confirm Password: ','>', 0).encode())
                            menuState += 1

                        elif menuid == 2 and menuState == 4:
                            email = theMessage
                            connection.send(formatParser('text','Email: ','>', 0).encode())
                            menuState += 1

                        elif userRegister == False:
                            connection.send(formatParser('text','Invalid username or password','>', 0).encode())
                            menuState = 0
                            menuid = 0

                        elif menuid == 3: ##FORGET PASSWORD
                            connection.send(formatParser('text',forgetPasswordMenu,'>', 0).encode())
                            menuState += 1

                        elif forgetPass == False:
                            connection.send(formatParser('text','Invalid email','>', 0).encode())
                            menuState = 0
                            menuid = 0

                        elif menuid == 4: ##doUserMenu
                            connection.send((formatParser('text','+==================================+\n\tUser Question Menu...\nUserID: {}\n+==================================+\n\n1. Take Quiz\n2. User results\n\n<ENTER> to go back to login page\n(You will be logged out)\n+==================================+\n\nPlease enter your choice:').format('username'), '>', 4+int(theMessage)).encode())

                        elif menuid == 5: ##Quiz
                            connection.send(formatParser('text', '+==================================+\n             Take Quiz\n+==================================+\n\nDo you want to take a quiz?\n1. Yes\n2. No\n\n<ENTER> to go Back\nPlease enter your choice: ','>', 0).encode())
                            menuState += 1

                        elif menuid == 5 and menuState == 1:
                            # MAIN QUIZ LOOP
                            pass

                        elif menuid == 6: ##View Results
                            connection.send((formatParser('text', '+==================================+\n             View Results\n+==================================+\nResults: \n\n{}. {}\n\n<ENTER> to go Back\nPlease enter your choice: ').format('i', 'results'),'>', 0).encode())
                            menuState += 1

                        elif menuid == 6 and menuState == 1:
                            connection.send((formatParser('text', '+==================================+\n           User Results\n+==================================+\nQuestions: \n\n{}. {}\n\n+==================================+\n           User Results\n+==================================+').format('i', 'results'),'>', 0).encode())
                            menuid = 4



                        if menuid < 0:
                            connection.send(formatParser('text', 'Goodbye', '>').encode())
                            remove_connection(connection)
                    else:
                        print('Message is not ascii')
                        pass
                except UnicodeDecodeError:
                    print('skipping non-ascii message')
                    pass
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

    LISTENING_PORT = 99

    try:
        # Create server and specifying that it can only handle 4 connections by time!
        socket_instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_instance.bind(('0.0.0.0', LISTENING_PORT))
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
            threading.Thread(target=handleUserConnection, args=[socket_connection, address]).start()

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
