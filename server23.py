
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
confirmPass = ""
courses = []
course = ""
class serverFunc():
    def menu(menuid, theMessage) -> str:
        menuid = int(menuid)
        global menuState
        global subMenu
        global username
        global password
        global confirmPass
        global course

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

        elif menuid == 2 and menuState == 0:  # REGISTER
            print('2')
            Courses = DBcom.UserDB.find(
                'users', 'AllCourses', 'id', 're', 'raw', '')

            for i in range(len(Courses)):
                courses.append(
                    str(int(i)+1) + '.' + base64.b64decode(Courses[i].split('_')[2]).decode('utf-8'))
            print(courses)

            course = str(courses).replace("[", "").replace("]", "").replace(
                ",", "\n").replace("'", "").replace(" ", "")

            whatToSend = formatParser(
                'text', '+==================================+\n\t    Register User\n+==================================+\nCourses:\n\n{}\n<Enter> to back\nPlease enter your Course: '.format(course))
            print(whatToSend)

            menuState += 1

        elif menuid == 2 and menuState == 1:
            print('2-1')
            username = theMessage
            whatToSend = (formatParser('regUser',registerRequirements,'>', 2).encode())
            menuState += 1

        elif menuid == 2 and menuState == 2:
            print('2-2')
            password = theMessage
            whatToSend = (formatParser('regPass','Password: ','>', 2).encode())
            menuState += 1

        elif menuid == 2 and menuState == 3:
            print('2-3')
            confirmPass = theMessage
            whatToSend = (formatParser('regPass','Confirm Password: ','>', 2).encode())
            menuState += 1

        elif menuid == 2 and menuState == 4:
            print('2-4')
            email = theMessage

            result = serverFunc.registerUser(course, username, password, email)
            whatToSend = (formatParser('email','Email: ','>', 2).encode())
            menuState += 1
            successorfail = result[0]
            label = result[1]

            if successorfail == True:
                whatToSend = (formatParser('text',label,'>', 1).encode())
                menuid = 4
                menuState = 0

        elif menuid == 3: ##FORGET PASSWORD
            whatToSend = (formatParser('email',forgetPasswordMenu,'>', 3).encode())
            menuState += 1

            if successorfail == True:
                whatToSend = (formatParser('text',label,'>', 1).encode())
                menuid = 4
                menuState = 0


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

    def registerUser(self, course, username, password, email):
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
            courses.append(i+1 +'.'+ base64.b64decode(Courses[i].split('_')[2]).decode('utf-8'))
        print('\n<ENTER> to back')
        if course > len(Courses):
            print('Please enter a valid number')
            return False, 'Invalid course'
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
        
        otp = str(generateOTP())

        #check if username is already taken
        if len(DBcom.UserDB.find('users', 'username', 'data','' , 'bool', username)) > 0:
            print('Username already taken')
            username_pass = False
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

                result = ('+==================================+')
                result +=('Registration successful,\nreturn to the menu to login!\n')
                result +=('your email is {}, recovery OTP is {}'.format(email, otp))
                result +=('+==================================+\n')
                return True, result
            except ValueError:
                return False, 'Error creating user'
        else:
            return False, 'Error creating user'

    def forgetPassword(self, localrowid, email):
        '''
        Purpose of this function is to allow the user to recover their password. (Theroeticaly)
        '''
        print('+==================================+')
        print('\t  Forget Password')
        print('+==================================+')
        print('\n<ENTER> to back')
        
        #check if email is valid

        if email == '':
            serverFunc.menu(localrowid)

        if re.match(r"[^@]+@[^@]+\.[^@]+", email) == None:
            print('Email is not valid')
            return False, 'Invalid email'
        else:
            try:
                localrowid = DBcom.UserDB.find('users', 'email', 'data','', 'id', email)[0]
            except IndexError:
                print('Email not found')
                return False, 'Email not found'
            if len(localrowid) != '':
                try:
                    #password = str(base64.b64decode(DBcom.UserDB.find('users', 'password', 'id','raw', localrowid[0])[0].split('_')[2]))[1:]
                    password = str(DBcom.UserDB.find('users', 'password', 'id','','raw', localrowid)).split('_')[2][0:-2]
                    result = ('+==================================+\n')
                    result +=('We have sent the password {} to your Email {}'.format(password,email))
                    result +=('+==================================+\n')
                    return True, result
                except:
                    return False, 'Error sending password'
            else:
                print('Email not found')
                return False, 'Email not found'

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
            serverFunc.userResults(localrowid, username)
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
    
    def takeQuiz(localrowid, username, preMadeQuiz):
        '''
        This function will take the user to the quiz page.
        It will display the questions and options for the user to answer.
        '''
        print('+==================================+\n')
        print(colors.fg.cyan, '\t     Take Quiz', colors.reset)
        print('+==================================+\n')
        #list the question pool
        resultList, allQnsList, resultQuestionPool = [], [], []
        #declaring the variables
        Opt = ['a', 'b', 'c', 'd']
        state = True
        forward, question, allOptnum = '', '', ''
        Qnscnt = 0
        Qnsid = 1
        #gets the current time for time taken for the quiz
        currentTime = time.time()

        #Finds the number of questions in the quiz that the admin has set
        Qnsno = DBcom.UserDB.find('questions', 'NumberOfQ', 'id', 're','raw','')
        Qnsno = int(Qnsno[0].split('_')[2])

        #Finds all the questions in the question pool and stores them in a list
        #note: the questions in this list are encoded
        allQns = DBcom.UserDB.find('questions', 'questions', 'id','re', 'raw','')

        #Finds all the options in the question pool and stores them in a list
        alloptions = DBcom.UserDB.find('questions', 'options', 'id', 're','raw','')

        #Finds the number of attempts the admin has set for the quiz
        attCount1 = DBcom.UserDB.find('questions', 'NumberOfAtt', 'id', 're', 'raw', '')
        attCount1 = int(attCount1[0].split('_')[2])

        #Finds the number of attempts the user has taken for the quiz
        attCount = DBcom.UserDB.find('users', 'AttemptNo', 'id', 're', 'raw', localrowid[0])
        attCount = base64.b64decode(attCount[0].split('_')[2]).decode('utf-8')

        #finds the number of questions set by the admin
        numberOfQuestions = DBcom.UserDB.find('questions', 'NumberOfQ', 'id', 're', 'raw', '')
        numberOfQuestions = str(numberOfQuestions[0]).split('_')[2]
        #print(numberOfQuestions)

        #Get the user's module and topics
        if preMadeQuiz == '1':
            userModule = '1__math_addition,subtraction'
        elif preMadeQuiz == '2':
            userModule = '2__isec_systemsec'
        else:
            userModule = DBcom.UserDB.find('users', 'userQuizCategory', 'id', 're', 'raw', localrowid[0])

        #print(userModule)
        p = 0
        topLen = len(str(userModule).split('_')[3].split(','))
        for i in range(topLen):
            qnBasedon_Module_Topic = str(userModule).split('_')[2] + '_' + str(userModule).split('_')[3].split(',')[p].replace(']','').replace('[','').replace("'","")
            for qn in allQns:
                qnIndex = qn.split('_')[2] + '_' + qn.split('_')[3]
                if qnBasedon_Module_Topic == qnIndex:
                    allQnsList.append(qn)
            p += 1
        
        #shuffle the questions

        #If the number of questions in question pool is less then the number of questons the admin set then the admin will be told that there are not enough questions in the question pool
        allQnscnt = len(allQnsList)
        if int(Qnsno) > int(allQnscnt):
            print('Error, there are not enough questions in the pool...')
            print('Please ask the admin to add more questions...')
            doUserQuestions(localrowid, username)
        #Get the current time that the user started the quiz
        
        #Check if the user has enough attempts to take the quiz
        if int(attCount) <= 0:
            print('You have no attempts left...')
            doUserQuestions(localrowid, username)
        
        #Main loop for the quiz
        while state == True:
            #If the user input is 'n' the user will go to the next question
            if forward == 'n':
                Qnscnt += 1
                Qnsid += 1
            #If the user input is 'p' the user will go to the previous question
            elif forward == 'p':
                Qnscnt -= 1
                Qnsid -=1
                #If the user is on the first question then they will be told that they are on the first question if 'p' is pressed
                try:
                    resultQuestionPool.pop(Qnscnt)
                    resultQuestionPool.pop(Qnscnt-1)
                    resultList.pop(Qnscnt)
                    resultList.pop(Qnscnt-1)
                except IndexError:
                    print('Error, you cannot go back on the first question')
                    Qnscnt += 1
                    Qnsid += 1
                    takeQuiz(localrowid, username, preMadeQuiz)
            #If the user input is 'e' the user will quit the quiz
            elif forward == 'e':
                print('Exiting Quiz...')
                doUserQuestions(localrowid, username)
            else:
                try:
                    resultQuestionPool.pop(Qnscnt)
                    resultList.pop(Qnscnt)
                except IndexError:
                    pass

            #The question displayed will be according to the index in the question List
            try:
                question = allQnsList[Qnscnt]
            except IndexError:
                pass

            #lets the user know what question they are on
            print("QuestionID: {}/{}".format(Qnsid, numberOfQuestions))
            print("Module: {}".format(question.split('_')[2]))
            print("Topic: {}".format(question.split('_')[3]))
            #prints the question from the question list decoded
            print("Question:\n{}".format(base64.b64decode(str(question.split('_')[4])).decode('utf-8')))
            #prints the options from the option list decoded according to the question's unique id

            for i in range(0, len(alloptions)):
                allOptnum = alloptions[i]
                if question.split('_')[0] == str(allOptnum).split('_')[0]:
                        allOptnum = allOptnum.split('_')[2]
                        allOptnum = base64.b64decode(str(allOptnum)).decode('utf-8')
                        allOptnum = allOptnum.split(',')
                        allOptnum = [x.strip() for x in allOptnum]
                        print("a) {}".format(str(allOptnum[0])))
                        print("b) {}".format(str(allOptnum[1])))
                        print("c) {}".format(str(allOptnum[2])))
                        print("d) {}".format(str(allOptnum[3])))
                        print('+==================================+')
                        print("What is the correct Answer?: ")
                        print('[a,b,c,d]')
                        #prompts the user to input their answer in the form of (a,b,c,d)
                        try:
                            result = str(input('> ')).lower()
                            #if the user input is valid then the user will be given the option to go to the next question and answer is stored in a list
                            if result in Opt:
                                resultList.append(result)
                                resultQuestionPool.append(question)
                                print('Answer saved.')
                            #if the user input is not in the form of (a,b,c,d) then the user will be told that they have not entered the correct answer
                            else:
                                print('Answer not in options')
                                print('Answer not saved.\n')
                            #print(len(resultList))
                            #print(len(resultQuestionPool))
                            print('+==================================+')
                            print('[p]revious, [n]ext, [e]xit.[p/n/e]')
                            try:
                                forward = str(input('> ')).lower()
                            except ValueError:
                                print('Invalid input...')
                                break
                        except ValueError:
                            print('Error, please enter a valid answer')
                            break
                #if the number of questions is equals to the current question number then the number of questions in the question pool then the user will be told that they have reached the end of the quiz
                if Qnsid == int(numberOfQuestions)+1:
                    print('You have reached the end of the quiz')
                    print('+==================================+')
                    print('Summary page:')
                    #prints the summary page consisting of questions asked and the user's answers
                    for i in range(0, len(resultList)):
                        try:
                            print('Question: {}\nAnswer:{}\n'.format(base64.b64decode(str(allQnsList[i].split('_')[4])).decode('utf-8'), resultList[i]))
                        except IndexError:
                            pass
                    print('+==================================+')
                    print('[y]es to submit. [p]revious to back.')
                    #asks the user if they want to submit the quiz
                    #if the user input is 'y' then the user will be submit the quiz
                    #if the user input is 'p' then the user will be taken back to the previous question
                    try:
                        submit = str(input('> '))
                    except ValueError:
                        print('Invalid input...')
                        takeQuiz(localrowid, username)
                    if submit == 'y':
                        clearConsole()
                        state = False
                        resultListUser = str(resultList)
                        resultListUser = resultListUser.replace("'","").replace("[","").replace("]","")
                        DBcom.UserDB.createQn('users', 'userAttAns', 's', localrowid[0], resultListUser)
                        attCount = int(attCount)
                        attCount -= 1
                        DBcom.UserDB.update('users', 'AttemptNo', 's', localrowid[0], str(attCount), '', '')

                        checkAnswer(localrowid, username, resultList, Qnsno, allQnsList, attCount, currentTime, resultQuestionPool, alloptions)
                        
                    else:
                        Qnscnt -= 1
                        Qnsid -= 1
                        resultQuestionPool.pop(Qnscnt)
                        resultQuestionPool.pop(Qnscnt-1)
                        resultList.pop(Qnscnt)
                        resultList.pop(Qnscnt-1)


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
        #try:
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
        #except Exception as e:
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
