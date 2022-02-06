import socket, threading
import json
import DBcom
import os
import base64
# Global variable that mantain client's connections
connections = []

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


def handle_user_connection(connection: socket.socket, address: str) -> None:
    '''
        Get user connection in order to keep receiving their messages and
        sent to others users/connections.
    '''

    # Purpose of this function is to create a account for the user.
    # The user is asked to enter their username, password, and email.
    # The username, password and email is checked to see if it already exists.
    # The password, username and email are hashed and stored in the database.
    def registerUser():
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
        print(colors.bold, colors.fg.cyan, '\t     Register User', colors.reset)
        print('+==================================+')
        print('Courses:')
        for i in range(len(Courses)):
            print('{}. {}'.format(i+1, base64.b64decode(Courses[i].split('_')[2]).decode('utf-8')))
        print('\n<ENTER> to back')
        connection.send(formatParser('text', 'Welcome to the registration page!', '>').encode())
        try:
            course = int(input('Please enter your Course: '))
        except ValueError:
            clearConsole()
            print(colors.fg.red, 'Please enter a valid number', colors.reset)
            registerUser(rowid)
        if course > len(Courses):
            clearConsole()
            print(colors.fg.red, 'Please enter a valid number', colors.reset)
            registerUser(rowid)
        else:
            course = base64.b64decode(Courses[course-1].split('_')[2]).decode('utf-8')
        print('+==================================+')
        print(colors.fg.cyan, '   Create User / Admin User Menu', colors.reset)
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
            clearConsole()
            menu(rowid)
        mat = re.search(patUser, username)
        if mat:
            pass
        else:
            clearConsole()
            print(colors.fg.red,'Username is not valid', colors.reset)
            registerUser(rowid)
        #if username is empty go back
        if username == '':
            clearConsole()
            menu(rowid)
        #check if password is valid
        password = str(input('Please enter your password: '))
        mat = re.search(patPass, password)
        if mat:
            pass
        else:
            clearConsole()
            print(colors.fg.red,'Password is not valid', colors.reset)
            registerUser(rowid)
        # ask user to confirm if password is correct
        password_confirm = str(input('Please confirm your password: '))
        if password == password_confirm:
            pass
        else:
            clearConsole()
            print(colors.fg.red,'Password does not match', colors.reset)
            registerUser(rowid)
        email = str(input('Please enter your email: '))
        otp = str(generateOTP())

        #check if username is already taken
        if len(DBcom.UserDB.find('users', 'username', 'data','' , 'bool', username)) > 0:
            print('Username already taken')
            registerUser(rowid)
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
                clearConsole()
                print(colors.fg.red,'Error creating user', colors.reset)
                registerUser(rowid)
        else:
            clearConsole()
            registerUser(rowid)

    while True:
        try:
            # Get client message
            msg = connection.recv(1024)

            # If no message is received, there is a chance that connection has ended
            # so in this case, we need to close connection and remove it from connections list.
            if msg:
                try:
                    msg_decoded = msg.decode('utf-8')
                # Log message sent by user
                    if str.isascii(msg_decoded):
                        print(f'{address[0]}:{address[1]} - {msg}')
                        jsonData = receiveParser(msg_decoded)
                        menu = jsonData['menuid']

                        if menu == 'login':
                            login(connection, jsonData)





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
                print('Error broadcasting message: {e}')
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

    LISTENING_PORT = 3000
    
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