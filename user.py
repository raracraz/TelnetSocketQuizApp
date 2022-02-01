# StudentID:	p2104089
# Name:	AAI XUN EN
# Class:		DISM/FT/1B/05   
# Assessment:	CA1 / CA2
# 
# Script name:	user.py
# 
# Purpose:	script to handle user login, register and forget password. Also to allow user to take quiz and view past results.
#
# Usage syntax:	Run with play button, press f5 to run
# 
# Input file:	jsonPython/db/...
# 
# Output file:	jsonPython/db/...
# 
# Python ver:	Python 3
#
#################################################################################
#                               Import Libraries                                #
#################################################################################
# os is used to navigate the directory, create files, delete files, update files, etc.
import os
# regex is used to check if input is valid.
import re
# base64 is used to encode the password for filename conventions.
import base64
# datetime is used to get the current date and time
import datetime
from threading import local
# DBcom is the database class that is used to access the filesystem commands.
import DBcom
# time is used to get the time taken to complete quiz.
import time
# uuid is used to generate a unique session id for the user.
import uuid
# hide password when login
import getpass

import base64

import pandas as pd

import socket as s
#############################################################################
#                                 menu                                      #
#############################################################################
# open connection to server using socket
s = s.socket(s.AF_INET, s.SOCK_STREAM)
s.connect(('localhost', 23))
#Purpose of this lambda function is to clear terminal after each input
clearConsole = lambda: os.system('cls')

#this is the main menu of the quiz app
#purpose of this menu is to provide the user with a menu to choose from

def menu(localrowid):
    #open connection to server using socket
    
    print('\n\n+==================================+')
    print(colors.bold, colors.fg.cyan, '      Welcome to The Quiz', colors.reset)
    print(' ________  ___  ___  ___   ________')     
    print('| \  __  \|\  \|\  \|\  \ |\_____  \ ')    
    print(' \ \ \ |\ \ \  \\ \\  \ \  \ \|___/  /|')   
    print('  \ \ \ \\\ \ \  \\ \\  \ \  \    /  / /   ')
    print('   \ \ \_\\\ \ \  \\_\\  \ \  \  /  /_/__')  
    print('    \ \_____ \ \_______\ \__\ |\_______\ ')
    print('     \|___|\__\|_______|\|__| \|_______|')
    print('          \|__|')
    print('+==================================+\n')    
    print('1. Login')
    print('2. Register')
    print('3. Forget password')
    print('\n<ENTER> to Exit')

# Get the user's choice to pass to the appropriate function.
    try:
        choice = int(input('Please enter your choice: '))
        if choice == 1:
            clearConsole()
            login(localrowid)
        elif choice == 2:
            clearConsole()
            registerUser(localrowid)
        elif choice == 3:
            clearConsole()
            forgetPassword(localrowid)
        else:
            clearConsole()
            menu(localrowid)
# if the user enters a non-integer (eg: spacebar) then program exits.
    except ValueError:
        print('Goodbye...')

        os._exit(0)
    menu(localrowid)

# The acls are the permissions that the user has on the system.
# The acls are stored in a string of length 8.
# The aclchecker function checks if the user has the permission to access the admin menu, or only the user menu.
'''
def aclchecker(localrowid, aclcheck):
    #rowid = DBcom.UserDB.find('users', 'username', 'data', 'id', username)
    aclraw = DBcom.UserDB.find('users', 'acl', 'id','re' , 'raw', localrowid)
    #print(aclraw)
    #print(localrowid)

    acl = str(base64.b64decode(aclraw[0].split('_')[2]))[1:]
    #print(acl)
    if acl[aclcheck] == '1':
        return True
    else:
        return False
'''
#############################################################################
#                           Part of register()                              #
#############################################################################
# Purpose of this function is to generate a random OTP for the user to use in password recovery.
def generateOTP():
    #get a random number then hash it to 8 digits
    randomNumber = os.urandom(16)
    randomNumber = abs(hash(randomNumber) % (10 ** 8))
    return randomNumber

# Purpose of this function is to create a account for the user.
# The user is asked to enter their username, password, and email.
# The username, password and email is checked to see if it already exists.
# The password, username and email are hashed and stored in the database.
def registerUser(rowid):
    '''
    Purpose of this function is to create a account for the user.
    '''
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

#############################################################################
#                           Part of forgetPassword()                        #
#############################################################################

# Purpose of this function is to send a email to the user with a OTP to reset their password. (In theory)
# (In actuallaity, the password is simulated to be reset by email)
# The user is asked to enter their email.
# The email is checked to see if it already exists.
# If the email is valid and exists then the password and sent to the user via email.
def forgetPassword(localrowid):
    '''
    Purpose of this function is to allow the user to recover their password. (Theroeticaly)
    '''
    print('+==================================+')
    print(colors.bold, colors.fg.cyan, '\t  Forget Password', colors.reset)
    print('+==================================+')
    print('\n<ENTER> to back')
    email = str(input('Please enter your email: '))
    
    #check if email is valid

    if email == '':
        clearConsole()
        menu(localrowid)

    if re.match(r"[^@]+@[^@]+\.[^@]+", email) == None:
        clearConsole()
        print('Email is not valid')
        forgetPassword(localrowid)
    else:
        try:
            localrowid = DBcom.UserDB.find('users', 'email', 'data','', 'id', email)[0]
        except IndexError:
            clearConsole()
            print('Email not found')
            forgetPassword(localrowid)
        if len(localrowid) != '':
            try:
                clearConsole()
                #password = str(base64.b64decode(DBcom.UserDB.find('users', 'password', 'id','raw', localrowid[0])[0].split('_')[2]))[1:]
                password = str(DBcom.UserDB.find('users', 'password', 'id','','raw', localrowid)).split('_')[2][0:-2]
                print('+==================================+\n')
                print('We have sent the password {} to your Email {}'.format(password,email))
                print('+==================================+\n')
                menu(localrowid)
            except:
                clearConsole()
                forgetPassword(localrowid)
        else:
            clearConsole()
            print('Email not found')
            forgetPassword(localrowid)

#############################################################################
#                           Part of login()                                 #
#############################################################################

# Purpose of this function is to login the user.
# The user is asked to enter their username and password.
# The username and password are checked to see if they exist.
# If the username and password are valid and exist then the user is logged in.

def login(localrowid):
    '''
    Purpose of this function is to login the user.
    '''
    print('+==================================+')
    print(colors.bold, colors.fg.cyan, '\t     Login Menu', colors.reset)
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
            password = getpass.getpass(prompt = 'Please enter your password: ')
        except ValueError:
            print(colors.bg.red,'Please enter a valid password', colors.reset)
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
                clearConsole()
                print('+==================================+')
                print(colors.fg.green ,'Login successful {}/{}'.format(username,localrowid), colors.reset)
                print('+==================================+')
                doUserQuestions(localrowid, username)
            else :
                clearConsole()
                print(colors.fg.red, 'a. Incorrect username or password', colors.reset)
                login(localrowid)
        except ValueError:
            clearConsole()
            print(colors.fg.red, 'b. Incorrect username or password', colors.reset)
            login(localrowid)
        except IndexError:
            clearConsole()
            print(colors.fg.red, 'c. Incorrect username or password', colors.reset)
            login(localrowid)
    except ValueError:
        clearConsole()
        login(localrowid)

#############################################################################
#                           After Logged in                                 #
#############################################################################

# Purpose of this function is to show the user the menu options.
# The user is asked to enter their choice.
# The choice is checked to see if it exists.
# If the choice is valid and exists then the user redirected to the correct function.
def doUserQuestions(localrowid, username):
    #print(userid)
    #userid = DBcom.UserDB.find('users', 'username', 'id', 'raw', localrowid)
    #print(userid)
    #userid = userid.split('_')[2]
    #userid = base64.b64decode(userid[0].split('_')[2]).decode('utf-8')
    #username = DBcom.UserDB.find('users', 'username', 'id', 'id', localrowid)
    #print(localrowid)
    #print(userid)
    print('+==================================+\n')
    print(colors.fg.cyan, '\tUser Question Menu...', colors.reset)
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
        menu(localrowid)
    if userChoice == 1:
        clearConsole()
        attCount = DBcom.UserDB.find('users', 'AttemptNo', 'id', 're', 'raw', localrowid[0])
        attCount = base64.b64decode(attCount[0].split('_')[2]).decode('utf-8')
        #asks user if they want to take a quiz
        print('+==================================+')
        print(colors.fg.cyan, '             Take Quiz', colors.reset)
        print('+==================================+\n')
        print('\nDo you want to take a quiz?')
        print('1. Yes')
        print('2. No')
        print('\n<ENTER> to go Back')
        try:
            choice = int(input('Please enter your choice: '))
            if choice == 1:
                clearConsole()
                try:
                    takeQuiz(localrowid, username, '')
                except IndexError:
                    clearConsole()
                    print(colors.fg.red, 'You have not been assigned a Module and Topics', colors.reset)
                    print('\nDo you wish to take a pre-made quiz?\n')
                    print('Quiz 1: Math - Addition, Subtraction')
                    print('Quiz 2: ISEC - System Security')
                    print('\n<ENTER> to go back')
                    choice = int(input('Please enter your choice: '))
                    if choice == 1:
                        clearConsole()
                        takeQuiz(localrowid, username, '1')
                    elif choice == 2:
                        clearConsole()
                        takeQuiz(localrowid, username, '2')
                    doUserQuestions(localrowid, username)
            elif choice == 2:
                clearConsole()
                doUserQuestions(localrowid, username)
            else:
                clearConsole()
                print(colors.fg.red,'Enter a valid choice...', colors.reset)
                doUserQuestions(localrowid, username)
        except ValueError:
            clearConsole()
            doUserQuestions(localrowid, username)
    elif userChoice == 2:
        userResults(localrowid, username)
    else:
        print('Invalid choice...')
        doUserQuestions(localrowid, username)
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
    

# Purpose of this function is to show the user their results.
# The results shown is based on the user's id.
# Other users will not be able to see the results of other users.
def userResults(localrowid, username):
    '''
    Purpose of this function is to allow the user to view all the results of the users.
    '''
    print('+==================================+')
    print(colors.fg.cyan, '         All User Results', colors.reset)
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
        clearConsole()
        print(colors.fg.yellow,'There are no results for this user...\n', colors.reset)
        doUserQuestions(localrowid, username)
    
    
    print('<ENTER> to go Back')
    try:
        choice = int(input('Please enter your choice: '))
        userChoice = userList[choice - 1]
        doUserShowQuestionInResults(localrowid, username, userChoice, UserAns, modelAns, userResult)
    except ValueError:
        clearConsole()
        doUserQuestions(localrowid, username)

    clearConsole()
    doUserQuestions(localrowid, username)

def doUserShowQuestionInResults(localrowid, username, userChoice, UserAns, modelAns, userResult):
    '''
    Purpose of this function is to allow the admin to view the results of the users.
    '''
    print('+==================================+')
    print(colors.fg.cyan, '         User Results', colors.reset)
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
    print(colors.fg.cyan, '         User Result', colors.reset)
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
#################################################################################
#                              takeQuiz + checkAnswer                           #
#################################################################################
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
        clearConsole()
        print(colors.fg.red,'Error, there are not enough questions in the pool...', colors.reset)
        print('Please ask the admin to add more questions...')
        doUserQuestions(localrowid, username)
    #Get the current time that the user started the quiz
    
    #Check if the user has enough attempts to take the quiz
    if int(attCount) <= 0:
        clearConsole()
        print(colors.fg.red,'You have no attempts left...', colors.reset)
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
            clearConsole()
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
                            clearConsole()
                        except ValueError:
                            print(colors.fg.red,'Invalid input...', colors.reset)
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
                    clearConsole()
                    print(colors.fg.red,'Invalid input...', colors.reset)
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
                    clearConsole()
                    Qnscnt -= 1
                    Qnsid -= 1
                    resultQuestionPool.pop(Qnscnt)
                    resultQuestionPool.pop(Qnscnt-1)
                    resultList.pop(Qnscnt)
                    resultList.pop(Qnscnt-1)

def checkAnswer(localrowid, username, resultList, Qnsno, allQnsList, attCount, currentTime, resultQuestionPool, alloptions):
    '''
    This function is used to check the user's answers and display the results, write results to the database and update the user's attempt number, update csv file
    '''
    print('+==================================+\n')
    print(colors.fg.cyan, '\tChecking Answer...', colors.reset)
    print('+==================================+\n')
    
    #declares the variables
    QnsList = []
    correctNum, score, counter = 0, 0, 0
    state = True
    Tscore = Qnsno*2
    #Finds the correct answer for each question
    modelAnsList = DBcom.UserDB.find('questions', 'correctAnswers', 'id', 're','raw','')
    #Finds the time taken for the user to end the quiz: endTime - startTime
    elapsedTime = time.time() - currentTime
    elapsedTime = round(elapsedTime, 2)

    #Finds number of attempts left for the user
    attemptsLeft = DBcom.UserDB.find('users', 'AttemptNo', 'id', 're', 'raw', localrowid[0])
    attemptsLeft = base64.b64decode(str(attemptsLeft[0]).split('_')[2]).decode('utf-8')

    print('User: {}'.format(username))
    #Finds the number of questions answered correctly and incorrectly
    '''
    for i in range(0, Qnsno):
        if base64.b64decode(modelAnsList[i].split('_')[2]).decode('utf-8') == resultList[i]:
            print('Question {}. Correct!'.format(i+1))
            correctNum = correctNum + 1
            score+=2
        else:
            print('Question {}. Incorrect!'.format(i+1))
    '''
    #print(resultList)
    #print(modelAnsList)
    for i in range(0, Qnsno):
        for modelAns in modelAnsList:
            if modelAns.split('_')[0] == allQnsList[i].split('_')[0]:
                modelAns = base64.b64decode(str(modelAns).split('_')[2]).decode('utf-8')
                print(modelAns)
                if modelAns == resultList[i]:
                    print('Question {}. Correct!'.format(i+1))
                    correctNum = correctNum + 1
                    score+=2
                    break
                else:
                    print('Question {}. Incorrect!'.format(i+1))
                    break
        
        

    #Finds the percentage of questions answered correctly
    percnt = (correctNum/Qnsno) * 100
    percnt = round(percnt, 2)
    #Finds the score of the user
    #Prints a results page with the user's score, percentage of questions answered correctly, and the time taken to complete the quiz
    print('\nFinal score: {}/{} - {}%'.format(score, Tscore, percnt))
    print('{}/{} questions correct.'.format(correctNum, Qnsno))
    print('Elapsed Time: {} seconds'.format(int(elapsedTime)))
    if percnt <= 40:
        print('\nPoor. You need to work harder.')
    elif percnt > 40 and percnt <= 60:
        print('\nFair. You can do better with more effort.')
    else:
        print('\nGood. Well done.')
    
    DBcom.UserDB.createQn('users', 'results', 's', localrowid[0], percnt)
    m = 0
    for result in resultQuestionPool:
        for option in alloptions:
            if str(option).split('_')[0] == str(result).split('_')[0]:
                DBcom.UserDB.createQn('users', 'userResultOptionPool', 'r', '0', str(option).split('_')[0]+'_'+str(option).split('_')[2]+'_'+str(m))
        for ans in modelAnsList:
            if str(ans).split('_')[0] == str(result).split('_')[0]:
                DBcom.UserDB.createQn('users', 'userResultAnsPool', 'r', '0', str(ans).split('_')[0]+'_'+str(ans).split('_')[2]+'_'+str(m))
        DBcom.UserDB.createQn('users', 'userResultQuestionPool', 'r', '0', str(result).split('_')[0]+'_'+str(result).split('_')[4]+'_'+str(m))
        DBcom.UserDB.createQn('users', 'userResultModulePool', 'r', '0', str(result).split('_')[0]+'_'+str(result).split('_')[2]+'_'+str(m))
        DBcom.UserDB.createQn('users', 'userResultTopicPool', 'r', '0', str(result).split('_')[0]+'_'+str(result).split('_')[3]+'_'+str(m))
        m =+ 1

    #write percnt and username to results.csv
    #find the total number of questions
    #find the number of questions answered correctly
    #write the percentage to the user's results.csv
    #write the time taken to the user's results.csv
    for i in range(0, Qnsno):
        Qns = allQnsList[i]
        Ans = resultList[i]
        Model = modelAnsList[i]
        #As the questions are in base64 format, we need to decode them before we can use them
        QnsList.append(base64.b64decode(Qns.split('_')[4]).decode('utf-8'))
        QnsList.append(Ans)
        QnsList.append(base64.b64decode(Model.split('_')[2]).decode('utf-8'))
    QnsList.append(str(elapsedTime)+' seconds')
    #As a the values are in a list, we need to convert them to a string and replace all unnessecary characters before storing them in the csv file
    QnsList = str(QnsList).replace('[', '').replace(']', '').replace("'", '')
    open('results.csv', 'a').write('\n{},{},{},{}'.format(username, str(QnsList.split(',')).replace('[', '').replace(']', '').replace("'", '').replace(' ', ''), str(percnt)+'%', datetime.datetime.now()))
    #ask if user wants to retake quiz
    while state == True:
        print('\nDo you want to retake the quiz?')
        #displays the number of tries the user has left to attempt the quiz
        attCount3 = DBcom.UserDB.find('questions', 'NumberOfAtt', 'id', 're', 'raw', '')
        print('[{}/{}] attempts left.'.format(attemptsLeft, attCount3[0].split('_')[2]))
        print('[y]es or [n]o')
        try:
            retake = str(input('Please enter your choice: ')).lower()
            if retake == 'y':
                #if the user wants to retake the quiz then the quiz will be reset
                #if the attempts left is equal to 0 then the user will be told that they have run out of attempts
                if attemptsLeft == 0:
                    clearConsole()
                    print(colors.bg.red, 'You have no more attempts left.', colors.reset)
                    doUserQuestions(localrowid, username)
                    print('+==================================+')
                    print('Thank you for taking the quiz.')
                    print('+==================================+')
                    state = False
                    doUserQuestions(localrowid, username)
                takeQuiz(localrowid, username)
            elif retake == 'n':
                clearConsole()
                print('+==================================+')
                print('Thank you for taking the quiz.')
                print('+==================================+')
                doUserQuestions(localrowid, username)
                state = False
            else:
                print(colors.fg.red,'Invalid input...', colors.reset)
        except ValueError:
            clearConsole()
            print(colors.fg.red,'Invalid input...', colors.reset)

        print('+==================================+\n')



###############################################################################
#                               Extra feature(colors)                         #
###############################################################################

# Python program to print
# colored text and background
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

# IF YOU WANT TO RUN THE USER SCRIPT WITHIN THE USER SCRIPT, UNCOMMENT THE FOLLOWING LINE
menu(localrowid = uuid.uuid4())
