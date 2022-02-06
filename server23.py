
import base64
import socket
import sys
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


    def login(localrowid):
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
                menu(localrowid)
            try:
                #password
                password = getpass.getpass(prompt = 'Please enter your password: ')
            except ValueError:
                print('Please enter a valid password')
                login(localrowid)
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
                    doUserQuestions(localrowid, username)
                else :
                    print('a. Incorrect username or password')
                    login(localrowid)
            except ValueError:
                print('b. Incorrect username or password')
                login(localrowid)
            except IndexError:
                print('c. Incorrect username or password')
                login(localrowid)
        except ValueError:
            login(localrowid)

def registerUser(rowid):
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
        registerUser(rowid)
    if course > len(Courses):
        print('Please enter a valid number')
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
        menu(rowid)
    mat = re.search(patUser, username)
    if mat:
        pass
    else:
        print('Username is not valid')
        registerUser(rowid)
    #if username is empty go back
    if username == '':
        menu(rowid)
    #check if password is valid
    password = str(input('Please enter your password: '))
    mat = re.search(patPass, password)
    if mat:
        pass
    else:
        print('Password is not valid')
        registerUser(rowid)
    # ask user to confirm if password is correct
    password_confirm = str(input('Please confirm your password: '))
    if password == password_confirm:
        pass
    else:
        print('Password does not match')
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
            print('Error creating user')
            registerUser(rowid)
    else:
        registerUser(rowid)

    def forgetPassword(localrowid):
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
            menu(localrowid)

        if re.match(r"[^@]+@[^@]+\.[^@]+", email) == None:
            print('Email is not valid')
            forgetPassword(localrowid)
        else:
            try:
                localrowid = DBcom.UserDB.find('users', 'email', 'data','', 'id', email)[0]
            except IndexError:
                print('Email not found')
                forgetPassword(localrowid)
            if len(localrowid) != '':
                try:
                    #password = str(base64.b64decode(DBcom.UserDB.find('users', 'password', 'id','raw', localrowid[0])[0].split('_')[2]))[1:]
                    password = str(DBcom.UserDB.find('users', 'password', 'id','','raw', localrowid)).split('_')[2][0:-2]
                    print('+==================================+\n')
                    print('We have sent the password {} to your Email {}'.format(password,email))
                    print('+==================================+\n')
                    menu(localrowid)
                except:
                    forgetPassword(localrowid)
            else:
                print('Email not found')
                forgetPassword(localrowid)

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

    def login() -> str:
        '''
        Login user
        '''

        # Get user name
        if username == '99':
            menu()
        print(username)

        # Get user password
        
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
        
        mat = re.search(patUser, username)
        if mat:
            pass

        if username == '':
            menu()

       
        mat = re.search(patPass, password)
        if mat:
            pass
        else:
            register()
        
        if password == password_confirm:
            pass
        else:
            register()
        # ask for email
        # email
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


        
                menu()
            except ValueError:
                
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
                                print('b. Incorrect username or password')
                                login(localrowid)
                            except IndexError:
                                print('c. Incorrect username or password')
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
