
import base64
import socket
import sys
import this
import threading

import DBcom
import glob
import os
import re
import json
import getpass

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
#                                classes                                    #
#############################################################################

class serverFunc():
    def menu(menuid, theMessage) -> str:
        
        userlogin = False
        userRegister = False
        forgetPass = False
        menuState = 0

        if menuid == 0:
            whatToSend = (formatParser('text',mainMenu,'>', 0).encode())

        elif menuid == 1: ##LOGIN
            whatToSend = (formatParser('text',loginMenu,'>', 0).encode())
            menuState += 1

        elif menuid == 1 and menuState == 1:
            username = theMessage
            whatToSend = (formatParser('text','Username: ','>', 1).encode())
            menuState += 1

        elif menuid == 1 and menuState == 2:
            password = theMessage
            whatToSend = (formatParser('text','Password: ','>', 1).encode())
            menuState += 1

        elif userlogin == False:
            whatToSend = (formatParser('text','Invalid username or password','>', 0).encode())
            menuState = 0
            menuid = 0

        elif menuid == 2: ##REGISTER
            courseChoice = theMessage
            whatToSend = (formatParser('text','+==================================+\n\t    Register User\n+==================================+\nCourses:\n\n{}. {}\n<Enter to back\nPlease enter your Course: >'.format('1', 'Courses'),'>', 0).encode())
            menuState += 1

        elif menuid == 2 and menuState == 1:
            username = theMessage
            whatToSend = (formatParser('text',registerRequirements,'>', 2).encode())
            menuState += 1

        elif menuid == 2 and menuState == 2:
            password = theMessage
            whatToSend = (formatParser('text','Password: ','>', 2).encode())
            menuState += 1

        elif menuid == 2 and menuState == 3:
            confirmPass = theMessage
            whatToSend = (formatParser('text','Confirm Password: ','>', 0).encode())
            menuState += 1

        elif menuid == 2 and menuState == 4:
            email = theMessage
            whatToSend = (formatParser('text','Email: ','>', 0).encode())
            menuState += 1

        elif userRegister == False:
            whatToSend = (formatParser('text','Invalid username or password','>', 0).encode())
            menuState = 0
            menuid = 0

        elif menuid == 3: ##FORGET PASSWORD
            whatToSend = (formatParser('text',forgetPasswordMenu,'>', 0).encode())
            menuState += 1

        elif forgetPass == False:
            whatToSend = (formatParser('text','Invalid email','>', 0).encode())
            menuState = 0
            menuid = 0

        elif menuid == 4: ##doUserMenu
            whatToSend = (formatParser('text','+==================================+\n\tUser Question Menu...\nUserID: {}\n+==================================+\n\n1. Take Quiz\n2. User results\n\n<ENTER> to go back to login page\n(You will be logged out)\n+==================================+\n\nPlease enter your choice:').format('username'), '>', 4+int(theMessage)).encode()

        elif menuid == 5: ##Quiz
            whatToSend = (formatParser('text', '+==================================+\n             Take Quiz\n+==================================+\n\nDo you want to take a quiz?\n1. Yes\n2. No\n\n<ENTER> to go Back\nPlease enter your choice: ','>', 0).encode())
            menuState += 1

        elif menuid == 5 and menuState == 1:
            # MAIN QUIZ LOOP
            pass

        elif menuid == 6: ##View Results
            whatToSend = (formatParser('text', '+==================================+\n             View Results\n+==================================+\nResults: \n\n{}. {}\n\n<ENTER> to go Back\nPlease enter your choice: ').format('i', 'results'),'>', 0).encode()
            menuState += 1

        elif menuid == 6 and menuState == 1:
            whatToSend = (formatParser('text', '+==================================+\n           User Results\n+==================================+\nQuestions: \n\n{}. {}\n\n+==================================+\n           User Results\n+==================================+').format('i', 'results'),'>', 0).encode()
            menuid = 4

        else:
            whatToSend = (formatParser('text', mainMenu,'>', 0).encode())

        return menuid, whatToSend


    def login(self, localrowid):
        '''
        Purpose of this function is to login the user.
        '''
        print('+==================================+')
        print('\t     Login Menu',)
        print('+==================================+')
        #declare variables
        username = ""
        password = ""
        username_pass = False
        password_pass = False
            
        try:
            print('\n<ENTER> to back')
            username = str(input('Please enter your username: '))
            #if there is no username entered.
            if username == '':
                print('+==================================+\n')
                print('Login terminated...\n')
                print('+==================================+\n')
                serverFunc.menu(localrowid)
            try:
                #password
                password = getpass.getpass(prompt = 'Please enter your password: ')
            except ValueError:
                print('Please enter a valid password')
                self.login(localrowid)
            rowid = DBcom.UserDB.find('users', 'username', 'data','', 'id', username)
            username_pass = DBcom.UserDB.find('users', 'username', 'data','','bool', username)
            password_pass = DBcom.UserDB.find('users', 'password', 'data','','bool', password)
            userid = DBcom.UserDB.find('users', 'username', 'id','', 'id', username)
            #print(localrowid)
            #print(userid)
            #print(rowid)
            localrowid = rowid
            try:
                #checks if the account has the nessesary permissions to login
                #acl = '00000' means no permissions to login admin menu
                #acl = '11111' means all permissions to login admin menu            
                #if the username and password are valid and exist then the user is logged in.
                #the logged in session will have a unique id according to the user logged in.
                if len(username_pass) > 0 and len(password_pass) > 0 and localrowid != '':
                    print('+==================================+')
                    print('Login successful {}/{}'.format(username,localrowid))
                    print('+==================================+')
                    #main menu for quiz
                    doUserQuestions(localrowid, username)
                else :
                    print('a. Incorrect username or password')
                    self.login(localrowid)
            except ValueError:
                print('b. Incorrect username or password')
                self.login(localrowid)
            except IndexError:
                print('c. Incorrect username or password')
                self.login(localrowid)
        except ValueError:
            self.login(localrowid)

    def registerUser(self, rowid):
        '''
        Purpose of this function is to create a account for the user.
        '''
        def generateOTP():
        #get a random number then hash it to 8 digits
            randomNumber = os.urandom(16)
            randomNumber = abs(hash(randomNumber) % (10 ** 8))
            return randomNumber
        username_pass = False
        email_pass = False
        #acl = '00000'
        #acl = '11111' #to create admin user
        #regenerate rowid to ensure each record is unique
        Attempts = DBcom.UserDB.find('questions', 'NumberOfAtt', 'id', 're','raw','')
        Attempts = Attempts[0].split('_')[2]
        localrowid = str(abs(hash(os.urandom(16)) % (10 ** 8)))
        Courses = DBcom.UserDB.find('users', 'AllCourses', 'id', 're','raw','')
        print('+==================================+')
        print('\t     Register User')
        print('+==================================+')
        print('Courses:')
        for i in range(len(Courses)):
            print('{}. {}'.format(i+1, base64.b64decode(Courses[i].split('_')[2]).decode('utf-8')))
        print('\n<ENTER> to back')
        try:
            course = int(input('Please enter your Course: '))
        except ValueError:
            print('Please enter a valid number')
            self.registerUser(rowid)
        if course > len(Courses):
            print('Please enter a valid number')
            self.registerUser(rowid)
        else:
            course = base64.b64decode(Courses[course-1].split('_')[2]).decode('utf-8')
            
        print('+==================================+')
        print('   Create User / Admin User Menu')
        print('+==================================+')
        print('Requirements:')
        print('1. Username must not contain special characters')
        print('2. Username/Password must be [4-20] characters')
        print('3. Password must contain at least one special character [@#$%^&+=]')
        print('4. Password must contain at least one upper and lower case letter')
        print('5. Password must contain at least one number [0-9]')
        print('<b> to back')
        print('+==================================+')
        #Username Requirements
        regUser = "^[a-zA-Z0-9]{4,20}$"
        patUser = re.compile(regUser)
        #Password Requirements
        regPass = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{4,20}$"
        patPass = re.compile(regPass)
        #Check if username is valid
        username = str(input('Please enter your username: '))
        if username == 'b':
            serverFunc.menu(rowid)
        mat = re.search(patUser, username)
        if mat:
            pass
        else:
            print('Username is not valid')
            self.registerUser(rowid)
        #if username is empty go back
        if username == '':
            serverFunc.menu(rowid)
        #check if password is valid
        password = str(input('Please enter your password: '))
        mat = re.search(patPass, password)
        if mat:
            pass
        else:
            print('Password is not valid')
            self.registerUser(rowid)
        # ask user to confirm if password is correct
        password_confirm = str(input('Please confirm your password: '))
        if password == password_confirm:
            pass
        else:
            print('Password does not match')
            self.registerUser(rowid)
        email = str(input('Please enter your email: '))
        otp = str(generateOTP())

        #check if username is already taken
        if len(DBcom.UserDB.find('users', 'username', 'data','' , 'bool', username)) > 0:
            print('Username already taken')
            self.registerUser(rowid)
        else:
            username_pass = True

        #check if email is a valid email
        if re.match(r"[^@]+@[^@]+\.[^@]+", email) == None:
            print('Email is not valid')
            email_pass = False
        else:
            email_pass = True

        #check if email is already taken
        if len(DBcom.UserDB.find('users', 'email', 'data','' ,'bool', email)) > 0:
            print('Email already taken')
            email_pass = False
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
                
            except ValueError:
                print('Error creating user')
                self.registerUser(rowid)
        else:
            self.registerUser(rowid)

    def forgetPassword(self, localrowid):
        '''
        Purpose of this function is to allow the user to recover their password. (Theroeticaly)
        '''
        print('+==================================+')
        print('\t  Forget Password')
        print('+==================================+')
        print('\n<ENTER> to back')
        email = str(input('Please enter your email: '))
        
        #check if email is valid

        if email == '':
            serverFunc.menu(localrowid)

        if re.match(r"[^@]+@[^@]+\.[^@]+", email) == None:
            print('Email is not valid')
            self.forgetPassword(localrowid)
        else:
            try:
                localrowid = DBcom.UserDB.find('users', 'email', 'data','', 'id', email)[0]
            except IndexError:
                print('Email not found')
                self.forgetPassword(localrowid)
            if len(localrowid) != '':
                try:
                    #password = str(base64.b64decode(DBcom.UserDB.find('users', 'password', 'id','raw', localrowid[0])[0].split('_')[2]))[1:]
                    password = str(DBcom.UserDB.find('users', 'password', 'id','','raw', localrowid)).split('_')[2][0:-2]
                    print('+==================================+\n')
                    print('We have sent the password {} to your Email {}'.format(password,email))
                    print('+==================================+\n')
                    serverFunc.menu(localrowid)
                except:
                    self.forgetPassword(localrowid)
            else:
                print('Email not found')
                self.forgetPassword(localrowid)

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
        print('Error: Client data is not in JSON format')
        return False



def handleUserConnection(connection: socket.socket, address: str) -> None:
    '''
        Get user connection in order to keep receiving their messages and
        sent to others users/connections.
    '''
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

                        connection.send(serverFunc.menu(menuid, theMessage, connection, address).encode())
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
