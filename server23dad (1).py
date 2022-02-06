
import base64
import socket
import sys
import this
import threading
import pandas as pd
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
userlogin = False
userRegister = False
forgetPass = False
menuState = 0
subMenu = 0
username = ""
password = ""
courses = []
class serverFunc():
    def menu(menuid, theMessage) -> str:
        menuid = int(menuid)
        global menuState
        global subMenu
        global username

        print('MenuId: {} / MenuState:{}'.format(menuid, menuState))

        if menuid == 0:
            print('0')
            menuid = theMessage
            whatToSend = (formatParser('text',mainMenu,'>', theMessage).encode())

        elif menuid == 1 and menuState == 0: ##LOGIN
            print('1')
            whatToSend = (formatParser('user','Username: ','>', 1).encode())
            menuState = 1

        elif menuid == 1 and menuState == 1:
            print('1-1')
            username = theMessage
            whatToSend = (formatParser('pass','Password for {}: '.format(username),'>', 1).encode())
            menuState = 2
        
        elif menuid == 1 and menuState == 2:
            print('1-2')
            password = theMessage
            
            result = serverFunc.login(username, password)
            successorfail = result[0]
            label = result[1]

            if successorfail == True:
                whatToSend = (formatParser('text',label,'>', 1).encode())
                menuid = 4
                menuState = 0
            else:
                whatToSend = (formatParser('user','{}\nUsername: '.format(label),'>', 1).encode())
                menuid=1
                menuState = 1

        elif menuid == 4 and menuState == 0:
            print('4')
            whatToSend = (formatParser('text',"show the quiz menu here\n\n",'>', 1).encode())
            menuState = 0

        elif userlogin == True:
            whatToSend = (formatParser('text','Invalid Choice','>', 0).encode())
            menuState = 0
            menuid = 0

        elif menuid == 2: ##REGISTER
            Courses = DBcom.UserDB.find('users', 'AllCourses', 'id', 're','raw','')
            for i in range(len(Courses)):
                courses.append('_' + i+1 +'.'+ base64.b64decode(Courses[i].split('_')[2]).decode('utf-8'))
            whatToSend = (formatParser('text','+==================================+\n\t    Register User\n+==================================+\nCourses:\n\n{}. {}\n<Enter> to back\nPlease enter your Course: '.format(str(courses).replace("[", "").replace("]", "").replace("_" "\n")),'>', 2).encode())
            menuState += 1

        elif menuid == 2 and menuState == 1:
            username = theMessage
            whatToSend = (formatParser('user',registerRequirements,'>', 2).encode())
            menuState += 1

        elif menuid == 2 and menuState == 2:
            password = theMessage
            whatToSend = (formatParser('pass','Password: ','>', 2).encode())
            menuState += 1

        elif menuid == 2 and menuState == 3:
            confirmPass = theMessage
            whatToSend = (formatParser('pass','Confirm Password: ','>', 2).encode())
            menuState += 1

        elif menuid == 2 and menuState == 4:
            email = theMessage
            whatToSend = (formatParser('email','Email: ','>', 2).encode())
            menuState += 1

        elif userRegister == True:
            whatToSend = (formatParser('text','Invalid username or password','>', 0).encode())
            menuState = 0
            menuid = 0

        elif menuid == 3: ##FORGET PASSWORD
            whatToSend = (formatParser('email',forgetPasswordMenu,'>', 3).encode())
            menuState += 1

        elif forgetPass == True:
            whatToSend = (formatParser('text','Invalid email','>', 0).encode())
            menuState = 0
            menuid = 0

        elif subMenu == 0: ##doUserMenu
            whatToSend = (formatParser(('text','+==================================+\n\tUser Question Menu...\nUserID: {}\n+==================================+\n\n1. Take Quiz\n2. User results\n\n<ENTER> to go back to login page\n(You will be logged out)\n+==================================+\n\nPlease enter your choice:').format('username'), '>', 0).encode())

        elif subMenu == 1: ##Quiz
            whatToSend = (formatParser('text', '+==================================+\n             Take Quiz\n+==================================+\n\nDo you want to take a quiz?\n1. Yes\n2. No\n\n<ENTER> to go Back\nPlease enter your choice: ','>', 0).encode())
            menuState += 1

        elif menuid == 5 and menuState == 1:
            # MAIN QUIZ LOOP
            pass

        elif subMenu == 2: ##View Results
            whatToSend = (formatParser('text', '+==================================+\n             View Results\n+==================================+\nResults: \n\n{}. {}\n\n<ENTER> to go Back\nPlease enter your choice: ').format('i', 'results'),'>', 0).encode()
            menuState += 1

        elif subMenu == 2 and menuState == 1:
            whatToSend = (formatParser('text', '+==================================+\n           User Results\n+==================================+\nQuestions: \n\n{}. {}\n\n+==================================+\n           User Results\n+==================================+').format('i', 'results'),'>', 0).encode()
            subMenu = 0

        else:
            whatToSend = (formatParser('text', mainMenu,'>', 0).encode())

        return menuid, whatToSend


    def login(username, password):
        '''
        Purpose of this function is to login the user.
        '''
        print('+==================================+')
        print('\t     Login Menu',)
        print('+==================================+')
        #declare variables
        username_pass = False
        password_pass = False
            
        try:
            print('\n<ENTER> to back')
            
            #if there is no username entered.
            
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
                    result = '+==================================+\n'
                    result += 'Login successful {}/{}'.format(username,localrowid)
                    result += '\n+==================================+'
                    #main menu for quiz
                    #serverFunc.doUserQuestions(localrowid, username)
                    return True,result
                else :
                    return False, 'Invalid username or password'
            except ValueError:
                return False, 'Invalid username or password'
            except IndexError:
                return False, 'Invalid username or password'
        except ValueError:
            return False, 'Invalid username or password'

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
            courses.append(i+1 +'.'+ base64.b64decode(Courses[i].split('_')[2]).decode('utf-8'))
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

    def doUserQuestions(self, localrowid, username):
        #print(userid)
        #userid = DBcom.UserDB.find('users', 'username', 'id', 'raw', localrowid)
        #print(userid)
        #userid = userid.split('_')[2]
        #userid = base64.b64decode(userid[0].split('_')[2]).decode('utf-8')
        #username = DBcom.UserDB.find('users', 'username', 'id', 'id', localrowid)
        #print(localrowid)
        #print(userid)
        print('+==================================+\n')
        print('\tUser Question Menu...')
        print('UserID: {}'.format(username))
        print('+==================================+\n')
        print('1. Take Quiz')
        print('2. User results')
        '''
        if aclchecker(localrowid[0], 4) == True:
            print('5. Admin Menu')
        '''
        print('\n<ENTER> to go back to login page')
        print('(You will be logged out)')
        print('+==================================+\n')
        try:
            userChoice = int(input('Please enter your choice: '))
        except ValueError:
            serverFunc.menu(localrowid)
        if userChoice == 1:
            attCount = DBcom.UserDB.find('users', 'AttemptNo', 'id', 're', 'raw', localrowid[0])
            attCount = base64.b64decode(attCount[0].split('_')[2]).decode('utf-8')
            #asks user if they want to take a quiz
            print('+==================================+')
            print('             Take Quiz',)
            print('+==================================+\n')
            print('\nDo you want to take a quiz?')
            print('1. Yes')
            print('2. No')
            print('\n<ENTER> to go Back')
            try:
                choice = int(input('Please enter your choice: '))
                if choice == 1:
                    try:
                        takeQuiz(localrowid, username, '')
                    except IndexError:
                        print('You have not been assigned a Module and Topics')
                        print('\nDo you wish to take a pre-made quiz?\n')
                        print('Quiz 1: Math - Addition, Subtraction')
                        print('Quiz 2: ISEC - System Security')
                        print('\n<ENTER> to go back')
                        choice = int(input('Please enter your choice: '))
                        if choice == 1:
                            takeQuiz(localrowid, username, '1')
                        elif choice == 2:
                            takeQuiz(localrowid, username, '2')
                        self.doUserQuestions(localrowid, username)
                elif choice == 2:
                    self.doUserQuestions(localrowid, username)
                else:
                    print('Enter a valid choice...')
                    self.doUserQuestions(localrowid, username)
            except ValueError:
                self.doUserQuestions(localrowid, username)
        elif userChoice == 2:
            userResults(localrowid, username)
        else:
            print('Invalid choice...')
            self.doUserQuestions(localrowid, username)
        '''
        elif userChoice == 5:
            try:
                if aclchecker(localrowid[0], 4) == True:
                    adminMenu(localrowid, username)
                else:
                    print('You do not have access to this menu')
                    menu(localrowid)
            except ValueError:
                pass
        '''
    def userResults(localrowid, username):
        '''
        Purpose of this function is to allow the user to view all the results of the users.
        '''
        print('+==================================+')
        print('         All User Results')
        print('+==================================+')
        count2, i = 1, 1
        count1, usercnt = 0, 0
        modelAns = []
        
        userList = DBcom.UserDB.find('users', 'results', 'id','re','raw', localrowid[0])
        userAnsList = DBcom.UserDB.find('users', 'userAttAns', 'id','re','raw', '')
        modelAnsList = DBcom.UserDB.find('questions', 'correctAnswers', 'id','re','raw', '')
        NumOfQues = DBcom.UserDB.find('questions', 'NumberOfQ', 'id','re','raw', '')
        '''
        for ans in modelAnsList:
            #only keep modelAnsList[2] which is the correct answers
            modelAns.append(ans.split('_')[2]) 
            #decode the base64 string to get the actual answers
            modelAns[count1] = base64.b64decode(modelAns[count1]).decode('utf-8')
            count1 += 1
        '''
        print('Results: \n')
        #displays the selected users results
        for results in userList:
            if localrowid[0] == results.split('_')[0]:
                date = results.split('_')[2]
                date = str(base64.b64decode(date).decode('utf-8'))
                userResult = results.split('_')[3]
                print('{}. {} - {}%'.format(i, date, userResult))
                for userAns in userAnsList:
                    TakenDate = userAns.split('_')[2]
                    TakenDate = str(base64.b64decode(TakenDate).decode('utf-8'))
                    UserAns = userAns.split('_')[3]
                    '''
                    if TakenDate == date:
                        while len(modelAns) > len(list(UserAns.split(','))):
                            modelAns.pop()
                        
                        print('User Answer:    {}'.format(UserAns))
                        print('Correct Answer: {}\n'.format(str(modelAns).replace('[','').replace(']','').replace("'",'')))
                    '''
                i += 1
                usercnt = 1
        #if the selected users hasnt attempted the quiz then it will display a message
        if usercnt == 0:
            print('There are no results for this user...\n')
            serverFunc.doUserQuestions(localrowid, username)
        
        
        print('<ENTER> to go Back')
        try:
            choice = int(input('Please enter your choice: '))
            userChoice = userList[choice - 1]
            serverFunc.doUserShowQuestionInResults(localrowid, username, userChoice, UserAns, modelAns, userResult)
        except ValueError:
            serverFunc.doUserQuestions(localrowid, username)

        serverFunc.doUserQuestions(localrowid, username)

    def doUserShowQuestionInResults(localrowid, username, userChoice, UserAns, modelAns, userResult):
        '''
        Purpose of this function is to allow the admin to view the results of the users.
        '''
        print('+==================================+')
        print('         User Results')
        print('+==================================+')
        List = ['a','b','c','d']
        modelAns = []
        count, i, anscount = 0, 1, 0
        # get the question list from the database
        QuestionList = DBcom.UserDB.find('users', 'userResultQuestionPool', 'id','re','raw', '')
        # get the option list from the database
        OptionList = DBcom.UserDB.find('users', 'userResultOptionPool', 'id','re','raw', '')
        # get the module list from the database
        ModuleList = DBcom.UserDB.find('users', 'userResultModulePool', 'id','re','raw', '')
        # get the topic list from the database
        TopicList = DBcom.UserDB.find('users', 'userResultTopicPool', 'id','re','raw', '')
        # get the correct answer list from the database
        CorrectAnswerList = DBcom.UserDB.find('users', 'userResultAnsPool', 'id','re','raw', '')
        for ans in CorrectAnswerList:
            #only keep CorrectAnswerList[2] which is the correct answers
            modelAns.append(base64.b64decode(ans.split('_')[3]).decode('utf-8'))
        for ans in modelAns:
            #decode the base64 string to get the actual answers
            ans = base64.b64decode(ans.split('_')[1]).decode('utf-8')
            modelAns[anscount] = ans
            anscount += 1

        print('Questions: \n')
        DateTaken = base64.b64decode(userChoice.split('_')[2]).decode('utf-8')
        for qn in QuestionList:
            if base64.b64decode(qn.split('_')[2]).decode('utf-8') == DateTaken:
                for mod in ModuleList:
                    if base64.b64decode(str(mod).split('_')[3]).decode('utf-8').split('_')[0] == base64.b64decode(str(qn).split('_')[3]).decode('utf-8').split('_')[0]:
                        Module = base64.b64decode(str(mod).split('_')[3]).decode('utf-8').split('_')[1]
                for top in TopicList:
                    if base64.b64decode(str(top).split('_')[3]).decode('utf-8').split('_')[0] == base64.b64decode(str(qn).split('_')[3]).decode('utf-8').split('_')[0]:
                        Topic = base64.b64decode(str(top).split('_')[3]).decode('utf-8').split('_')[1]

                print('ID: {}'.format(i))
                print('Module: {}'.format(Module.upper()))
                print('Topic: {}'.format(Topic.upper()))
                print('Question: {}'.format(base64.b64decode(str(base64.b64decode(qn.split('_')[3]).decode('utf-8')).split('_')[1]).decode('utf-8')))

                for opt in OptionList:
                    if str(base64.b64decode(qn.split('_')[3]).decode('utf-8')).split('_')[0] == base64.b64decode(opt.split('_')[3]).decode('utf-8').split('_')[0] and base64.b64decode(opt.split('_')[2]).decode('utf-8') == DateTaken:
                        print('a) {}'.format(base64.b64decode(base64.b64decode(opt.split('_')[3]).decode('utf-8').split('_')[1]).decode('utf-8').replace(' ','').split(',')[0]))
                        print('b) {}'.format(base64.b64decode(base64.b64decode(opt.split('_')[3]).decode('utf-8').split('_')[1]).decode('utf-8').replace(' ','').split(',')[1]))
                        print('c) {}'.format(base64.b64decode(base64.b64decode(opt.split('_')[3]).decode('utf-8').split('_')[1]).decode('utf-8').replace(' ','').split(',')[2]))
                        print('d) {}'.format(base64.b64decode(base64.b64decode(opt.split('_')[3]).decode('utf-8').split('_')[1]).decode('utf-8').replace(' ','').split(',')[3]))
                print('\n')
                count += 1
                i += 1

        UserAns = list(UserAns.replace('[','').replace(']','').replace(",",'').replace(" ",''))

        print('+==================================+')
        print('         User Result')
        print('+==================================+')
        print('Date: {}'.format(DateTaken))
        print('Result: {}%'.format(userResult))
        print('\n')
        # use pandas to compare the users answers with the correct answers horitzontally
        # if the user answer is correct then the user gets 'correct'
        # if the user answer is incorrect then the user gets 'incorrect'
        # index should start at 1
        df = pd.DataFrame(list(zip(UserAns, modelAns)), columns = ['UserAns', 'ModelAns'])
        df['Result'] = df.apply(lambda x: 'Correct' if x['UserAns'] == x['ModelAns'] else 'Incorrect', axis=1)
        df.index += 1
        print(df)
        # ask user if they want to print a graph of the results
        print('\n')
        input('<ENTER> to go Back ')


#############################################################################
#                               functions                                   #
#############################################################################

def formatParser(theType, theMessage,thePrompt='>', menuid = 0, minLength=1,maxLength=512,minVal=1,maxVal=99):
    jsonStr = {'type': theType, 'message': theMessage, 'prompt': thePrompt, 'minLength': minLength, 'maxLength': maxLength, 'minVal': minVal, 'maxVal': maxVal,'menuid': menuid}
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
    
    connection.send(formatParser('text', mainMenu, '>', 0).encode())
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
                        

                        if int(menuid) < 0:
                            print('Goodnight...')
                            remove_connection(connection)
                            break
                        connection.send(serverFunc.menu(menuid, theMessage)[1])
                    else:
                        print('Message is not ascii')
                        pass
                except UnicodeDecodeError:
                    print('skipping non-ascii message')
                    pass
            else:
                print('Connection closed')
                remove_connection(connection)
                break
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

    LISTENING_PORT = 3000

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
