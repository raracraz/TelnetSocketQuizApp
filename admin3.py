# StudentID:	p2104089
# Name:	AAI XUN EN
# Class:		DISM/FT/1B/05   
# Assessment:	CA1 / CA2
# 
# Script name:	admin.py
# 
# Purpose:	script to provide the admin menu to change settings of the quiz app
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
# random is used to randomize the question order
import random
# uuid is used to generate a unique session id for the user.
import uuid
# make password hidden
import getpass
# pandas to generate a report
import pandas as pd
# matplotlib is used to generate a graph of the quiz results.
import matplotlib.pyplot as plt

import socket as s
#################################################################################
#                                     menu                                      #
#################################################################################
# open connection to server using socket
s = s.socket(s.AF_INET, s.SOCK_STREAM)
s.connect(('localhost', 23))

#Purpose of this lambda function is to clear terminal after each input
clearConsole = lambda: os.system('cls')

#this is the main menu of the quiz app
#purpose of this menu is to provide the user with a menu to choose from
def menu(localrowid):
    '''
    Purpose of this function is to provide the user with a menu to choose from
    '''
    print('\n\n+==================================+')
    print(colors.bold, colors.fg.cyan, '   Welcome to The Admin menu', colors.reset)
    print(' ________  ___  ___  ___  ________')     
    print('| \  __  \|\  \|\  \|\  \ |\_____  \ ')    
    print(' \ \ \ |\ \ \  \\ \\  \ \  \ \|___/  /|')   
    print('  \ \ \ \\\ \ \  \\ \\  \ \  \    /  / /   ')
    print('   \ \ \_\\\ \ \  \\_\\  \ \  \  /  /_/__')  
    print('    \ \_____ \ \_______\ \__\ |\_______\ ')
    print('     \|___|\__\|_______|\|__| \|_______|')
    print('          \|__|')
    print('+==================================+\n')    
    print('1. Login')
    print('2. Forget password')
    print('\n<ENTER> to Exit')

# Get the user's choice to pass to the appropriate function.
    try:
        choice = int(input('Please enter your choice: '))
        clearConsole()
        if choice == 1:
            login(localrowid)
        elif choice == 2:
            forgetPassword(localrowid)
        else:
            menu(localrowid)
# if the user enters a non-integer (eg: spacebar) then program exits.
    except ValueError:
        print('Goodbye...')

        os._exit(0)
    menu(localrowid)

#################################################################################
#                                    login                                      #
#################################################################################
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
            clearConsole()
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
            if aclchecker(localrowid, 1) == False:
                clearConsole()
                print(localrowid)
                print(colors.fg.red, 'c. You do not have access to this system', colors.reset)
                menu(localrowid)
            else:
                #if the username and password are valid and exist then the user is logged in.
                #the logged in session will have a unique id according to the user logged in.
                if len(username_pass) > 0 and len(password_pass) > 0 and localrowid != '':
                    clearConsole()
                    print('+==================================+')
                    print(colors.fg.green ,'Login successful {}/{}'.format(username,localrowid), colors.reset)
                    print('+==================================+')
                    adminMenu(localrowid, username)

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
# The acls are the permissions that the user has on the system.
# The acls are stored in a string of length 5.
# The aclchecker function checks if the user has the permission to access the admin menu, or only the user menu.
# The aclchecker function returns True if the user has the permission to access the admin menu.
#acl = '00000' means no permissions to login admin menu
#acl = '11111' means all permissions to login admin menu
def aclchecker(localrowid, aclcheck):
    #Finds the acl of the user according to the user's localrowid
    aclraw = DBcom.UserDB.find('users', 'acl', 'id','re' , 'raw', localrowid)
    #decode the acl string
    acl = str(base64.b64decode(aclraw[0].split('_')[2]))[1:]
    if acl[aclcheck] == '1':
        return True
    else:
        return False

#################################################################################
#                               Register User                                   #
#################################################################################

# Purpose of this function is to generate a random OTP for the user to use in password recovery.
def generateOTP():
    '''
    Purpose of this function is to generate a random OTP for the user to use in password recovery.
    '''
    #get a random number then hash it to 8 digits
    randomNumber = os.urandom(16)
    randomNumber = abs(hash(randomNumber) % (10 ** 8))
    return randomNumber

# Purpose of this function is to create a account for the user.
# The user is asked to enter their username, password, and email.
# The username, password and email is checked to see if it already exists.
# The password, username and email are hashed and stored in the database.
def registerUser(rowid, fromwhere, acl = '11111'):
    '''
    Purpose of this function is to create a admin account for the user.
    '''
    username_pass = False
    email_pass = False
    #acl = '00000'
    #acl = '11111' #to create admin user
    #regenerate rowid to ensure each record is unique
    Attempts = DBcom.UserDB.find('questions', 'NumberOfAtt', 'id', 're','raw','')
    Attempts = Attempts[0].split('_')[2]
    localrowid = str(abs(hash(os.urandom(16)) % (10 ** 8)))
    #let the user choose what course he is registering for
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
        registerUser(rowid, fromwhere)
    if course > len(Courses):
        clearConsole()
        print(colors.fg.red, 'Please enter a valid number', colors.reset)
        registerUser(rowid, fromwhere)
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
        menu(localrowid)
    mat = re.search(patUser, username)
    if mat:
        pass
    else:
        clearConsole()
        print(colors.fg.red,'Username is not valid', colors.reset)
        registerUser(rowid,fromwhere)
    #if username is empty go back
    if username == '':
        clearConsole()
        menu(localrowid)
    #check if password is valid
    password = str(input('Please enter your password: '))
    mat = re.search(patPass, password)
    if mat:
        pass
    else:
        clearConsole()
        print(colors.fg.red,'Password is not valid', colors.reset)
        registerUser(rowid,fromwhere)
    # ask user to confirm if password is correct
    password_confirm = str(input('Please confirm your password: '))
    if password == password_confirm:
        pass
    else:
        clearConsole()
        print(colors.fg.red,'Password does not match', colors.reset)
        registerUser(rowid, fromwhere)
    email = str(input('Please enter your email: '))
    otp = str(generateOTP())

    #check if username is already taken
    if len(DBcom.UserDB.find('users', 'username', 'data','' , 'bool', username)) > 0:
        print('Username already taken')
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
            
            DBcom.UserDB.create('users', 'acl', 's', localrowid, acl)
            DBcom.UserDB.create('users', 'username', 's', localrowid, username)
            DBcom.UserDB.create('users', 'password', 's', localrowid, password)
            DBcom.UserDB.create('users', 'otp', 's', localrowid, str(otp))
            DBcom.UserDB.create('users', 'email', 's', localrowid, email)
            DBcom.UserDB.create('users', 'AttemptNo', 's', localrowid, str(Attempts))
            DBcom.UserDB.create('users', 'UserCourses', 's', localrowid, course)
            clearConsole()
            print('+==================================+')
            print('Registration successful,\nreturn to the menu to login!\n')
            print('your email is {}, recovery OTP is {}'.format(email,otp))
            print('+==================================+\n')
            
            if fromwhere == "admin":
                doAdminUser(rowid, username)
            else:
                clearConsole()
                menu(rowid)
        except ValueError:
            clearConsole()
            print(colors.fg.red,'Error creating user', colors.reset)
            registerUser(localrowid,fromwhere)
    else:
        clearConsole()
        registerUser(localrowid,fromwhere)

#################################################################################
#                              Forget password                                  #
#################################################################################

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

#################################################################################
#                          admin menu + admin features                          #
#################################################################################

def adminMenu(localrowid, username):
    '''
    Purpose of this function is to allow the admin to perform admin functions.
    '''
    print('+==================================+\n')
    print(colors.fg.cyan, '    Welcome to the admin menu', colors.reset)
    print('+==================================+\n')
    print('1. User settings')
    print('2. Question settings')
    print('3. Take Quiz')
    print('4. All User Results')
    print('\n<ENTER> to go Back')
    try:
        choice = int(input('Please enter your choice: '))
    except ValueError:
        clearConsole()
        menu(localrowid)
    if choice == 1:
        clearConsole()
        doAdminUser(localrowid, username)
    elif choice == 2:
        clearConsole()
        doAdminQuestions(localrowid, username)
    elif choice == 3:
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
                takeQuiz(localrowid, username)
            elif choice == 2:
                clearConsole()
                adminMenu(localrowid, username)
            else:
                clearConsole()
                print(colors.fg.red,'Enter a valid choice...', colors.reset)
                adminMenu(localrowid, username)
        except ValueError:
            clearConsole()
            adminMenu(localrowid, username)

        #finds how many questions did the admin set
        #clearConsole()
        #takeQuiz(localrowid, username, count = attCount)
    elif choice == 4:
        clearConsole()
        doAdminResults(localrowid, username)
    else:
        clearConsole()
        adminMenu(localrowid, username)

def doAdminListResults(rowid, username, localrowid):
    '''
    Purpose of this function is to allow the admin to view all the results of the users.
    '''
    print('+==================================+')
    print(colors.fg.cyan, '         All User Results', colors.reset)
    print('+==================================+')
    count2, i = 1, 1
    count1, usercnt = 0, 0
    localrowid = localrowid[0]
    modelAns = []
    
    userList = DBcom.UserDB.find('users', 'results', 'id','re','raw', rowid)
    userAnsList = DBcom.UserDB.find('users', 'userAttAns', 'id','re','raw', '')
    modelAnsList = DBcom.UserDB.find('questions', 'correctAnswers', 'id','re','raw', '')
    NumOfQues = DBcom.UserDB.find('questions', 'NumberOfQ', 'id','re','raw', '')

    for ans in modelAnsList:
        #only keep modelAnsList[2] which is the correct answers
        modelAns.append(ans.split('_')[2]) 
        #decode the base64 string to get the actual answers
        modelAns[count1] = base64.b64decode(modelAns[count1]).decode('utf-8')
        count1 += 1
    
    print('Results: \n')
    #displays the selected users results
    for results in userList:
        if rowid == results.split('_')[0]:
            date = results.split('_')[2]
            date = str(base64.b64decode(date).decode('utf-8'))
            userResult = results.split('_')[3]
            print('{}. {} - {}%'.format(i, date, userResult))
            for userAns in userAnsList:
                TakenDate = userAns.split('_')[2]
                TakenDate = str(base64.b64decode(TakenDate).decode('utf-8'))
                UserAns = userAns.split('_')[3]
                if TakenDate == date:
                    while len(modelAns) > len(list(UserAns.split(','))):
                        modelAns.pop()
                    
                    print('User Answer:    {}'.format(UserAns))
                    print('Correct Answer: {}\n'.format(str(modelAns).replace('[','').replace(']','').replace("'",'')))
            i += 1
            usercnt = 1
    #if the selected users hasnt attempted the quiz then it will display a message
    if usercnt == 0:
        clearConsole()
        print(colors.fg.yellow,'There are no results for this user...\n', colors.reset)
        adminMenu(localrowid, username)
    
    
    print('<ENTER> to go Back')
    try:
        choice = int(input('Please enter your choice: '))
        userChoice = userList[choice - 1]
        doAdminShowQuestionInResults(localrowid, username, userChoice, UserAns, modelAns, userResult)
    except ValueError:
        clearConsole()
        adminMenu(localrowid, username)

    clearConsole()
    adminMenu(localrowid, username)

def doAdminShowQuestionInResults(localrowid, username, userChoice, UserAns, modelAns, userResult):
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


def doAdminResults(localrowid, username):
    '''
    Purpose of this function is to allow the admin to view the results of the users.
    '''
    print('+==================================+\n')
    print(colors.fg.cyan, '         All User Results', colors.reset)
    print('+==================================+\n')
    usercount = 1
    allusers = DBcom.UserDB.find('users', 'username', 'id', 're','raw','')
    alluserscnt = len(allusers)
    #displays all users

    for user in allusers:

        print("{}. Username: {} / UserID: {}".format(usercount,str(base64.b64decode(user.split('_')[2]))[2:-1],str(user.split('_')[0])))
        usercount = usercount + 1
    print('\n<ENTER> to go Back')
    #prompts the user to select a user to view results
    try:
        choice = int(input('Please enter your choice [{}-{}]: '.format(1,alluserscnt)))
    except ValueError:
        clearConsole()
        adminMenu(localrowid, username)

    if choice > alluserscnt or choice < 1:
        clearConsole()
        print(colors.fg.red,'Enter a valid choice...', colors.reset)
        adminMenu(localrowid, username)
    else:
        clearConsole()
        rowid = allusers[choice-1].split('_')[0]
        doAdminListResults(rowid, username, localrowid)
    #List all users
    #Let the user choose which user to view results
    #List all results for that user
    

def doAdminUser(localrowid, username):#debug
    '''
    Purpose of this function is to allow the admin to change user settings or create a admin account.
    '''
    print('+==================================+\n')
    print(colors.fg.cyan, ' Welcome to the user setting menu', colors.reset)
    print('+==================================+\n')
    print('1. Create new user')
    print('2. List Users to Update/Delete')
    print('3. Select Module/Topic for User ')
    print('4. Course Options')
    print('\n<ENTER> to go Back')
    try:
        choice = int(input('Please enter your choice: '))
    except ValueError:
        clearConsole()
        adminMenu(localrowid, username)
    if choice == 1:
        clearConsole()
        registerUser(localrowid, fromwhere='admin')
    elif choice == 2:
        clearConsole()
        doAdminListUsers(localrowid)
    elif choice == 3:
        clearConsole()
        doAdminListUserForModule(localrowid, username)
    elif choice == 4:
        clearConsole()
        doAdminCourseOptions(localrowid, username)
    else:
        clearConsole()
        print(colors.fg.red,'Enter a valid choice...', colors.reset)
        adminMenu(localrowid, username)

def doAdminCourseOptions(localrowid, username):
    '''
    Purpose of this function is to allow the admin to add a course to the database.
    '''
    print('+==================================+\n')
    print(colors.fg.cyan, '         Add Course', colors.reset)
    print('+==================================+\n')
    print('1. Add Course')
    print('2. List Courses')
    print('3. Delete Courses')
    print('\n<ENTER> to go Back')
    try:
        choice = int(input('Please enter your choice: '))
    except ValueError:
        clearConsole()
        adminMenu(localrowid, username)
    if choice == 1:
        clearConsole()
        addCourse(localrowid, username)
    elif choice == 2:
        clearConsole()
        doAdminListCourses(localrowid)
    elif choice == 3:
        clearConsole()
        doAdminListDeleteCourses(localrowid, username)
    else:
        clearConsole()
        print(colors.fg.red,'Enter a valid choice...', colors.reset)
        adminMenu(localrowid, username)

def doAdminListDeleteCourses(localrowid, username):
    '''
    Purpose of this function is to allow the admin to delete a course from the database.
    '''
    print('+==================================+\n')
    print(colors.fg.cyan, '         Delete Course', colors.reset)
    print('+==================================+\n')
    #List all courses
    courses = DBcom.UserDB.find('users', 'AllCourses', 'id','re' , 'raw', '')
    print('\n')
    for course in courses:
        print('{}. {}'.format(courses.index(course)+1, base64.b64decode(course.split('_')[2]).decode('utf-8')))
    print('\n<ENTER> to go Back')
    try:
        choice = int(input('Please enter your choice: '))
    except ValueError:
        clearConsole()
        adminMenu(localrowid, username)
    if choice > len(courses) or choice < 1:
        clearConsole()
        print(colors.fg.red,'Enter a valid choice...', colors.reset)
        adminMenu(localrowid, username)
    else:
        clearConsole()
        course = courses[choice-1]
        rowid = course.split('_')[0]
        print('Are you sure you want to delete {}?'.format(base64.b64decode(course.split('_')[2]).decode('utf-8')))
        print('1. Yes')
        print('2. No')
        try:
            choice = int(input('Please enter your choice: '))
        except ValueError:
            clearConsole()
            adminMenu(localrowid, username)
        if choice == 1:
            clearConsole()
            DBcom.UserDB.deleteUser('users', 'AllCourses', rowid)
            print('{} has been deleted'.format(base64.b64decode(course.split('_')[2]).decode('utf-8')))
            print('\n<ENTER> to go Back')
            try:
                choice = int(input('Please enter your choice: '))
            except ValueError:
                clearConsole()
                adminMenu(localrowid, username)
            if choice == 1:
                clearConsole()
                adminMenu(localrowid, username)
        elif choice == 2:
            clearConsole()
            adminMenu(localrowid, username)
        else:
            clearConsole()
            print(colors.fg.red,'Enter a valid choice...', colors.reset)
            adminMenu(localrowid, username)

def addCourse(localrowid, username):
    '''
    Purpose of this function is to allow the admin to add a course to the database.
    '''
    print('+==================================+\n')
    print(colors.fg.cyan, '         Add Course', colors.reset)
    print('+==================================+\n')
    rowid = int(localrowid[0]) + random.randint(1,1000000)
    print('Do you want to add a new course?')
    print('1. Yes')
    print('2. No')
    print('\n<ENTER> to go Back')
    try:
        choice = int(input('Please enter your choice: '))
    except ValueError:
        clearConsole()
        adminMenu(localrowid, username)
    if choice == 1:
        course = input('Please enter the course name: ').upper()
        #check if course already exists
        if len(DBcom.UserDB.find('users', 'AllCourses', 'data','' , 'bool', course)) > 0:
            clearConsole()
            print(colors.fg.red,'Course already exists...', colors.reset)
            adminMenu(localrowid, username)
        elif len(course) > 4:
            clearConsole()
            print(colors.fg.red,'Course name too long...', colors.reset)
            adminMenu(localrowid, username)
        # if course name has a number in it then it is not valid
        elif any(char.isdigit() for char in course):
            clearConsole()
            print(colors.fg.red,'Course name cannot have a number...', colors.reset)
            adminMenu(localrowid, username)
        else:
            DBcom.UserDB.create('users', 'AllCourses', 's', str(rowid), course)
            clearConsole()
            print(colors.fg.green,'Course added...', colors.reset)
            adminMenu(localrowid, username)
    elif choice == 2:
        clearConsole()
        adminMenu(localrowid, username)
    else:
        clearConsole()
        print(colors.fg.red,'Enter a valid choice...', colors.reset)
        adminMenu(localrowid, username)

def doAdminListCourses(localrowid):
    '''
    Purpose of this function is to allow the admin to list all the courses in the database.
    '''
    print('+==================================+\n')
    print(colors.fg.cyan, '         List Courses', colors.reset)
    print('+==================================+\n')
    try:
        courses = DBcom.UserDB.find('users', 'AllCourses', 'id', 're','raw','')
        print('Course Names: ')
        print('\n'.join(base64.b64decode(courses.split('_')[2]).decode('utf-8') for courses in courses))
    except IndexError:
        print(colors.fg.yellow, 'No courses found...', colors.reset)

    print('\n<ENTER> to go Back')
    input()
    clearConsole()
    adminMenu(localrowid, '')


def doAdminUserEditData(userid, column, value, localrowid):
    '''
    Purpose of this function is to allow the admin to edit the users data.
    '''
    # column 1 = 'username'
    # column 2 = 'password'
    # column 3 = 'email'
    # column 4 = 'acl'
    # column 5 = 'otp'
    if column == 1:
        DBcom.UserDB.update('users', 'username', 's',userid, value, '', '')
    elif column == 2:
        DBcom.UserDB.update('users', 'password', 's',userid, value, '', '')
    elif column == 3:
        DBcom.UserDB.update('users', 'email', 's',userid, value, '', '')
    elif column == 4:
        DBcom.UserDB.update('users', 'acl', 's',userid, value, '', '')
    elif column == 5:
        DBcom.UserDB.update('users', 'otp', 's',userid, value, '', '')

    doAdminUserEditList(userid, localrowid)

def doAdminUserDelData(userid, localrowid, username):
    '''
    Purpose of this function is to allow the admin to delete the users data.
    '''
    #confirms user choice to delete user
    print('Are you sure you want to delete this user? [y/n]')
    try:
        choice = str(input('Please enter your choice: ').lower())
        if choice == 'y':
            #deletes user from filesystem
            DBcom.UserDB.deleteUser('users', 'username', userid)
            DBcom.UserDB.deleteUser('users', 'password',userid)
            DBcom.UserDB.deleteUser('users', 'email', userid)
            DBcom.UserDB.deleteUser('users', 'acl', userid)
            DBcom.UserDB.deleteUser('users', 'otp', userid)
            clearConsole()
            print('Deleted User successfully')
            doAdminUser(localrowid, username)
        elif choice == 'n':
            clearConsole()
            doAdminUserEditList(userid, localrowid)
        else:
            clearConsole()
            (colors.fg.red,'Enter a valid choice...', colors.reset)
            doAdminUserEditList(userid, localrowid)
    except ValueError:
        clearConsole()
        print(colors.fg.red,'Enter a valid choice...', colors.reset)
        doAdminUserEditList(userid, localrowid)

def doAdminUserEditList(userid, localrowid):
    '''
    Purpose of this function is to allow the admin to edit the users data.
    '''
    #finds the users data: username, acl, password, email, otp
    username = DBcom.UserDB.find('users', 'username', 'id','re', 'raw', userid)
    acl = DBcom.UserDB.find('users', 'acl', 'id', 're','raw', userid)
    password = DBcom.UserDB.find('users', 'password', 'id', 're','raw', userid)
    otp = DBcom.UserDB.find('users', 'otp', 'id', 're','raw', userid)
    email = DBcom.UserDB.find('users', 'email', 'id', 're','raw', userid)
    AttemptNo = DBcom.UserDB.find('users', 'AttemptNo', 'id', 're','raw', userid)
    #as the user data is encoded, it needs to be decoded
    username = str(base64.b64decode(username[0].split('_')[2]))[2:-1]
    password = str(base64.b64decode(password[0].split('_')[2]))[2:-1]
    otp = str(base64.b64decode(otp[0].split('_')[2]))[2:-1]
    email = str(base64.b64decode(email[0].split('_')[2]))[2:-1]
    acl = str(base64.b64decode(acl[0].split('_')[2]))[2:-1]
    AttemptNo = str(base64.b64decode(AttemptNo[0].split('_')[2]))[2:-1]
    print('+==================================+')
    print(colors.fg.cyan, '        Edit user settings', colors.reset)
    print('+==================================+')
    print('User: [{}]'.format(username))
    print('\n')
    print('1. username:{}'.format(username))
    print('2. password:{}'.format(password))
    print('3. email:{}'.format(email))
    print('4. acl:{}'.format(acl))
    print('5. otp:{}'.format(otp))
    print('6. DELETE USER')
    print('7. Reset Quiz Attempts')
    print('   -  Current Attempts: {}'.format(AttemptNo))
    print('\n<ENTER> to go Back')
    try:
        choice = int(input('Please enter your choice [1-7]: '))

        if choice == '':
            clearConsole()
            doAdminListUsers(localrowid)
        elif choice == 6:
            clearConsole()
            doAdminUserDelData(userid, localrowid, username)
        elif choice == 7:
            clearConsole()
            doAdminResetAttempts(userid, localrowid, username)
        elif choice > 7:
            clearConsole()
            print(colors.fg.red,'Enter a valid choice...', colors.reset)
            doAdminUserEditList(userid, localrowid)
        else:
            print('\n<ENTER> to go Back')
            changeTo = input('Please enter the new value: ')
            if changeTo == '':
                clearConsole()
                doAdminListUsers(localrowid)
            else:
                clearConsole()
                doAdminUserEditData(userid, choice, changeTo, localrowid)
    except ValueError:
        clearConsole()
        doAdminListUsers(localrowid)

def doAdminListUsers(localrowid):
    '''
    Purpose of this function is to allow the admin to list users to edit data.
    '''
    print('+==================================+\n')
    print(colors.fg.cyan, '\t   List of Users', colors.reset)
    print('+==================================+\n')
    userlist = []
    usercount = 1
    allusers = DBcom.UserDB.find('users', 'username', 'id', 're','raw','')
    alluserscnt = len(allusers)
    #displays all users with userid
    for user in allusers:
        print("{}. Username: {} / UserID: {}".format(usercount,str(base64.b64decode(user.split('_')[2]))[2:-1],str(user.split('_')[0])))
        usercount = usercount + 1

    print('\n<ENTER> to go Back')

    try:
        choice = int(input('Please enter your choice [{}-{}]: '.format(1,alluserscnt)))
    except ValueError:
        clearConsole()
        doAdminUser(localrowid, '')
    #if user selection is valid, it will display the users data
    if choice > alluserscnt:
        clearConsole()
        print(colors.fg.red,'Enter a valid choice...', colors.reset)
        doAdminUser(localrowid, '')
    else:
        clearConsole()
        rowid = allusers[choice-1].split('_')[0]
        doAdminUserEditList(rowid, localrowid)

def doAdminListUserForModule(localrowid, username):
    '''
    Purpose of this function is to allow the admin to list modules to choose from
    '''
    print('+==================================+\n')
    print(colors.fg.cyan, '\t   Select Modules', colors.reset)
    print('+==================================+\n')
    #finds all modules
    usercount = 1
    choice = 0
    allusers = DBcom.UserDB.find('users', 'username', 'id', 're','raw','')
    alluserscnt = len(allusers)
    #displays all users with userid
    for user in allusers:
        print("{}. Username: {} / UserID: {}".format(usercount,str(base64.b64decode(user.split('_')[2]))[2:-1], str(user.split('_')[0])))
        usercount = usercount + 1

    print('\n<ENTER> to go Back')

    try:
        choice = int(input('Please enter your choice [{}-{}]: '.format(1,alluserscnt)))
    except ValueError:
        clearConsole()
        doAdminQuestions(localrowid, username)
    #if user selection is valid, it will display the users data
    if choice > alluserscnt:
        clearConsole()
        print(colors.fg.red,'Please enter a valid choice', colors.reset)
        doAdminQuestions(localrowid, username)
    else:
        clearConsole()
        userid = allusers[choice-1].split('_')[0]
        doAdminSelectModuleForUser(userid, localrowid, username)

def doAdminSelectModuleForUser(userid, localrowid, username):
    '''
    Purpose of this function is to allow the admin to select a module and topic for a user
    '''
    print('+==================================+\n')
    print(colors.fg.cyan, '\t   Select Modules', colors.reset)
    print('+==================================+\n')
    #asks users to select a module
    allQns = DBcom.UserDB.find('questions', 'questions', 'id', 're','raw','')
    count = 1
    state, loop = True, False
    Module, Topic, resMod, resTopic, userChoiceTopList, userTempChoiceTopList = [], [], [], [], [], []
    #asks the user to select Module and Topic and shows the questions
    print('Which Module do you want to Select?')
    print('Current Modules:\n')

    #CHOOSE MODULES
    for x in allQns:
        Module.append(x.split('_')[2])
    #remove duplicates in Module List 
    [resMod.append(x) for x in Module if x not in resMod]
    for mod in resMod:
        print('{}. {}'.format(count, mod.upper()))
        count += 1

    print('\n<ENTER> to go back')
    try:
        userChoiceMod = int(input('Please enter your choice: '))
        userChoiceMod = resMod[userChoiceMod-1]
    except ValueError:
        clearConsole()
        doAdminQuestions(localrowid, username)
    except IndexError:
        clearConsole()
        print(colors.fg.red,'Please enter a valid choice', colors.reset)
        doAdminQuestions(localrowid, username)
        
    print('\n')
    #CHOOSE TOPIC
    while state == True:
        count2 = 1
        print('Which Topic do you want to Select?')
        print('Current Topics:\n')
        for x in allQns:
            if x.split('_')[2] == userChoiceMod:
                Topic.append(x.split('_')[3])

        #remove duplicates in Topic List
        [resTopic.append(x) for x in Topic if x not in resTopic]
        if len(resTopic) == 0:
            print('No Topics available')
            doAdminListUserForModule(localrowid, username)
        for top in resTopic:
            print('{}. {}'.format(count2, top.upper()))
            count2 += 1

        print('\n<ENTER> to go back')
        try:
            userChoiceTop = int(input('Please enter your choice: '))
        
            if loop == False:
                # does not allow user to enter duplicate topics
                userChoiceTopList.append(resTopic[userChoiceTop-1])
                loop = True

            else:
                userChoiceTopList = resTopic[userChoiceTop-1]
            
            #remove duplicate values in userChoiceTopList 
            [userTempChoiceTopList.append(x) for x in userChoiceTopList if x not in userTempChoiceTopList]

            loop = True
            print('\n')
        except ValueError:
            clearConsole()
            doAdminQuestions(localrowid, username)
        except IndexError:
            clearConsole()
            print(colors.fg.red,'Please enter a valid choice', colors.reset)
            doAdminQuestions(localrowid, username)
        
        while loop == True:
            clearConsole()
            print('Do you want to select another Topic?')
            print('1. Yes')
            print('2. No')
            try:
                print('\n<ENTER> to go back')
                userChoice = int(input('Please enter your choice: '))
                print('\n')
            except ValueError:
                clearConsole()
                doAdminQuestions(localrowid, username)
            if userChoice == 1:
                clearConsole()
                loop = False
            elif userChoice == 2:
                clearConsole()
                loop = False
                state = False
            else:
                clearConsole()
                print(colors.fg.red,'Please enter a valid choice', colors.reset)

    #topics selected by the user are stored in a list and changed to a string
    userTempChoiceTopList = str(userTempChoiceTopList).replace('[','').replace(']','').replace("'",'').replace(' ','')

    #Let module and topics be selected on the same strinng
    value = str(userChoiceMod) + '_' + str(userTempChoiceTopList)
    boolvalue = DBcom.UserDB.find('users', 'userQuizCategory', 'id', '','data', userid)
    #print(str(boolvalue).split('_')[2] +'_'+ str(boolvalue).split('_')[3][:-2])
    #Check if the user has selected the modules and topics before
    try:
        #Update the Category if the user has selected the modules and topics before
        clearConsole()
        if value == str(boolvalue).split('_')[2] +'_'+ str(boolvalue).split('_')[3][:-2] and str(userid) == str(boolvalue).split('_')[0][2:]:
            print('\nYou have already selected this module and topic')
            doAdminListUserForModule(localrowid, username)
        else:
            clearConsole()
            DBcom.UserDB.update('users', 'userQuizCategory', '', userid, value, '', '')
            print('\nYou have selected the module and topic')
            doAdminListUserForModule(localrowid, username)
    #If the user has not selected the modules and topics before >>
    except IndexError:
        clearConsole()
        DBcom.UserDB.createQn('users', 'userQuizCategory', '', userid, value)
        print('\nYou have selected the module and topic')
        doAdminListUserForModule(localrowid, username)


def doAdminResetAttempts(userid, localrowid, username):
    '''
    Purpose of this function is to allow the admin to reset the attempts of a user
    '''
    #resets all users attempts
    OriAttempts = DBcom.UserDB.find('questions', 'NumberOfAtt', 'id', 're','raw','')
    OriAttempts = OriAttempts[0].split('_')[2]
    DBcom.UserDB.update('users', 'AttemptNo', 's', userid, OriAttempts, '', '')
    clearConsole()
    print('\nReset user [ {} ] attempts successfully.\n'.format(username))
    doAdminListUsers(localrowid)

def doAdminRandomizeQuestions(localrowid, username):
    '''
    Purpose of this function is to allow the admin to randomize the questions
    '''
    print('+==================================+\n')
    print(colors.fg.cyan, '\tRandomizing Questions...', colors.reset)
    print('+==================================+\n')
    #get the list of questions
    allQns = DBcom.UserDB.find('questions', 'questions', 'id', 're','raw','')
    CorrectAns = DBcom.UserDB.find('questions', 'correctAnswers', 'id', 're','raw','')
    #shuffle the list
    AnsQns = list(zip(allQns, CorrectAns))
    print(AnsQns)
    random.shuffle(AnsQns)
    allQns, CorrectAns = zip(*AnsQns)
    allQns = list(allQns)
    CorrectAns = list(CorrectAns)
    for qn in allQns:
        qnid = qn.split('_')[0]
        qn = str(qn.split('_')[2])
        DBcom.UserDB.update('questions', 'questions', 'r', qnid, qn, '', '')
    for ans in CorrectAns:
        ansid = ans.split('_')[0]
        ans = str(ans.split('_')[2])
        DBcom.UserDB.update('questions', 'correctAnswers', 'r', ansid, ans, '', '')
    clearConsole()
    print('+==================================+\n')
    print('Questions randomized successfully!')
    print('+==================================+\n')
    adminMenu(localrowid, username)

def doAdminQuestions(rowid, username): #Debug
    '''
    Purpose of this function is to provide a menu for the admin to choose settings from
    '''
    print('+==================================+\n')
    print(colors.fg.cyan, '     Question settings menu', colors.reset)
    print('+==================================+\n')
    print('1. Update/Delete questions')
    print('2. Add questions to pool')
    print('3. Randomize questions')
    print('4. Number of Questions')
    print('5. Number of Quiz attempts')
    print('6. Change header for the CSV result file')
    print('\n<ENTER> to go Back')
    print('+==================================+\n')
    try:
        choice = int(input('Please enter your choice: '))
    except ValueError:
        clearConsole()
        adminMenu(rowid, username)
    if choice == 1:
        clearConsole()
        doAdminlistQuestionPool(rowid, username)
    elif choice == 2:
        clearConsole()
        doAdminAddQuestions(rowid, username)
    elif choice == 3:
        clearConsole()
        doAdminRandomizeQuestions(rowid, username)
    elif choice == 4:
        clearConsole()
        adminSelectQuestions(rowid, username)
    elif choice == 5:
        clearConsole()
        doAdminSelectAttempts(rowid, username)
    elif choice == 6:
        clearConsole()
        doAdminSelectHeader(rowid, username)
    else:
        clearConsole()
        adminMenu(rowid, username)

def doAdminSelectHeader(localrowid, username):
    '''
    Purpose of this function is to allow the admin to change the header of the CSV result file
    '''
    current = DBcom.UserDB.find('questions', 'NumberOfQ', 'id', 're', 'raw', '')
    current = (current[0].split('_')[2])
    current = int(current)
    QnsList = []
    Username = 'User'
    questionName = 'Question'
    UansName = 'User Answer'
    MansName = 'Model Answer'
    TimeName = 'Elapsed Time'
    ScoreName = 'Score'
    DateName = 'Date'
    print('Current Header:')
    print('{} | {} | {} | {} | {} | {} | {}'.format(Username, questionName,UansName,MansName,TimeName,ScoreName,DateName))
    print('\n<ENTER> to go Back')
    print('+==================================+\n')
    print('Are you sure you want to change the Header?')
    print('[y/n]')
    try:
        choice = str(input('Please enter your choice: ')).lower()
        if choice == 'y':
            print('Please enter the new Header:')
            Username = str(input('User: '))
            questionName = str(input('Question: '))
            UansName = str(input('User Answer: '))
            MansName = str(input('Model Answer: '))
            TimeName = str(input('Elapsed Time: '))
            ScoreName = str(input('Score: '))
            DateName = str(input('Date: '))
            print('+==================================+\n')
        else:
            print('+==================================+\n')
            clearConsole()
            print(colors.fg.red,'Header not changed\n',colors.reset)
            adminMenu(localrowid, username)
    except ValueError:
        clearConsole()
        adminMenu(localrowid, username)
    QnsList.append(Username)
    for i in range(1, current+1):
        QnsList.append('{} {}'.format(questionName, str(i)))
        QnsList.append('{}'.format(UansName))
        QnsList.append('{}'.format(MansName))
    QnsList.append('{}'.format(TimeName))
    QnsList.append('{}'.format(ScoreName))
    QnsList.append('{}'.format(DateName)) 
    #write a new header into results.csv
    #print(QnsList)
    open('results.csv', 'a').write('\n{}'.format(str(str(QnsList).split(',')).replace('"','').replace("'", '').replace('[', '').replace(']', '').replace(' ', '')))
    print('+==================================+\n')
    clearConsole()
    print('Header changed successfully!')
    doAdminQuestions(localrowid, username)

def doAdminSelectAttempts(localrowid, username):
    '''
    Purpose of this function is to allow the admin to change the number of attempts for the quiz
    '''
    print('+==================================+\n')
    print(colors.fg.cyan, '     Set Number of Quiz Attempts', colors.reset)
    print('+==================================+\n')
    current = DBcom.UserDB.find('questions', 'NumberOfAtt', 'id', 're', 'raw', '')
    current = current[0].split('_')[2]
    print('\n<ENTER> to go Back')
    print('Current number of Attempts: {}'.format(current))
    try:
        userChoice = int(input('\nPlease enter your choice: '))
        if userChoice == '':
            clearConsole()
            doAdminQuestions(localrowid, username)
    except ValueError:
        clearConsole()
        print('Please enter a valid choice')
        doAdminQuestions(localrowid, username)
    if userChoice >= 1 and userChoice <= 10:
        DBcom.UserDB.update('questions', 'NumberOfAtt', 'q', '0', userChoice, '', '')
        clearConsole()
        print('+==================================+\n')
        print('Number of Attempts set successfully!')
        doAdminQuestions(localrowid, username)

def doAdminAddQuestions(localrowid, username): #add questions to the pool
    '''
    Purpose of this function is to allow the admin to add questions to the pool
    '''
    print('+==================================+\n')
    print(colors.fg.cyan, '\tAdd Questions', colors.reset)
    print('+==================================+\n')
    allQns = DBcom.UserDB.find('questions', 'questions', 'id', 're','raw','')
    count, count2 = 1, 1
    Module, Topic, resMod, resTopic = [], [], [], []
    print('What Module do you wish to Add to/Create: ')
    print('Current Modules:\n')
    for x in allQns:
        Module.append(x.split('_')[2])
    #remove duplicates in Module List 
    [resMod.append(x) for x in Module if x not in resMod]
    for mod in resMod:
        print('{}'.format(mod.upper()))
        count += 1

    print('\n<ENTER> to go back')
    try:
        modChoice = str(input('Please enter the Module Name: ').lower())
        if modChoice == '':
            clearConsole()
            doAdminQuestions(localrowid, username)
    except ValueError:
        clearConsole()
        print('Please enter a valid choice')
        doAdminQuestions(localrowid, username)
        
    print('\n')
    #CHOOSE TOPIC
    print('Which Topic do you want to Select?')
    print('Current Topics:\n')
    for x in allQns:
        if x.split('_')[2] == modChoice:
            Topic.append(x.split('_')[3])

    #remove duplicates in Topic List
    [resTopic.append(x) for x in Topic if x not in resTopic]
    try:
        for top in resTopic:
            print('{}'.format(top.upper()))
            count2 += 1
    except IndexError:
        print('No Topics available')
        pass

    print('\n<ENTER> to go back')
    try:
        topicChoice = str(input('Please enter the Topic Name: ').lower())
        if topicChoice == '':
            clearConsole()
            doAdminQuestions(localrowid, username)
    except ValueError:
        clearConsole()
        doAdminQuestions(localrowid, username)
    
    print('\n<ENTER> to go Back')
    '''
    try:
        modChoice = str(input('Please enter your choice: ')).lower()
    except ValueError:
        doAdminQuestions(localrowid, username)
    print('\nWhat Topic do you wish to Add/Create: ')
    try:
        topicChoice = str(input('\nPlease enter your choice: ')).lower()
    except ValueError:
        doAdminQuestions(localrowid, username)
    '''
    print('\nHow many questions do you want to add?')
    print('(max 10)')
    print('\n<ENTER> to go back')
    try:
        questionCount = int(input('> '))
    except ValueError:
        clearConsole()
        doAdminQuestions(localrowid, username)
    if questionCount < 1 or questionCount > 10:
        clearConsole()
        print(colors.fg.red,'Enter valid number of questions...', colors.reset)
        doAdminQuestions(localrowid, username)
    else:
        for i in range(1,questionCount+1):
            options = []
            opt = ['a','b','c','d']
            questionid = os.urandom(16)
            questionid = abs(hash(questionid) % (10 ** 8))
            print('\nCreating Question {}'.format(i))
            print('What is the question?')
            question = input('> ')
            question+str(i)
            #question = question.encode('utf-8')
            for j in range(1,5):
                print('What is the option {}?'.format(opt[j-1]))
                inputOptions = input('> ')
                #inputOptions = inputOptions.encode('utf-8')
                options.append(inputOptions)
            print('What is the correct answer?')
            print('[a, b, c ,d]')
            correctAnswer = input('> ')
            #correctAnswer = correctAnswer.encode('utf-8')

            if correctAnswer not in opt:
                print('Error, the correct answer is not in the options...')
                doAdminAddQuestions(localrowid, username)
            options = str(options)
            #print(type(options))
            options = options.replace("'","").replace('[','').replace(']','')
            #print(options)
            try:
                DBcom.UserDB.create('questions','options','s',questionid,options)
                DBcom.UserDB.create('questions','correctAnswers','s',questionid,correctAnswer)
                DBcom.UserDB.createMod('questions', 'questions', 'qn', modChoice, topicChoice, questionid, question)
                print('Question {} created successfully'.format(i))
            except OSError:
                clearConsole()
                print(colors.fg.red,'Error creating question pool', colors.reset)
                print('Please try again')
                doAdminAddQuestions(localrowid, username)
        clearConsole()
        print('+==================================+\n')
        print('\n')
    doAdminQuestions(localrowid, username)

def adminSelectQuestions(localrowid, username):
    '''
    Purpose of this function is to allow the admin to select questions from the pool
    '''
    print('+==================================+\n')
    print(colors.fg.cyan, '   Select Number of Questions', colors.reset)
    print('+==================================+\n')
    print('How many questions should the Quiz have?')
    print('\n<ENTER> to go Back')
    QnsList = []
    current = DBcom.UserDB.find('questions', 'NumberOfQ', 'id', 're', 'raw', '')
    current = current[0].split('_')[2]
    print('Current number of questions: {}'.format(current))
    try:
        userChoice = int(input('\nPlease enter your choice: '))
        if userChoice == '':
            clearConsole()
            doAdminQuestions(localrowid, username)
    except ValueError:
        clearConsole()
        print('Please enter a valid choice')
        doAdminQuestions(localrowid, username)
    if userChoice >= 5 and userChoice <= 10:
        #print(choice)
        DBcom.UserDB.update('questions', 'NumberOfQ', 'q', '0', userChoice, '', '')
        for i in range(1, userChoice+1):
            QnsList.append('Question-{}'.format(i))
            QnsList.append('User Answer')
            QnsList.append('Model Answer')
        QnsList.append('Elapsed Time')
        QnsList.append('Score')
        QnsList.append('Date') 
        #write a new header into results.csv
        #print(QnsList)
        open('results.csv', 'a').write('\n{},{}'.format('User',str(str(QnsList).split(',')).replace('"','').replace("'", '').replace('[', '').replace(']', '').replace(' ', '')))
        clearConsole()
        print('+==================================+\n')
        print('Number of Questions set successfully!')
        doAdminQuestions(localrowid, username)
    

def doAdminCreateQuestionPool(localrowid, username):
    '''
    Purpose of this function is to allow the admin to create a question pool (not used)
    '''
    print('+==================================+\n')
    print(colors.fg.cyan, '\tCreate Question Pool', colors.reset)
    print('+==================================+\n')
    #create the question pool
    #delete current questions
    DBcom.UserDB.delete('questions', 'questions')
    DBcom.UserDB.delete('questions', 'options')
    DBcom.UserDB.delete('questions', 'correctAnswers')
    print('How many questions do you want to have in the quiz?')
    print('(max 10)')
    print('\n<ENTER> to go back')
    
    try:
        questionCount = int(input('> '))
    except ValueError:
        print('Please enter a valid choice')
        adminMenu(localrowid, username)
    if questionCount < 1 or questionCount > 10:
        print('Invalid number of questions...')
        adminMenu(localrowid, username)
    else:
        for i in range(1,questionCount+1):
            options = []
            opt = ['a','b','c','d']
            questionid = os.urandom(16)
            questionid = abs(hash(questionid) % (10 ** 8))
            print('\nCreating Question {}'.format(i))
            print('What is the question?')
            question = input('> ')
            question+str(i)
            #question = question.encode('utf-8')
            for j in range(1,5):
                print('What is the option {}?'.format(opt[j-1]))
                inputOptions = input('> ')
                #inputOptions = inputOptions.encode('utf-8')
                options.append(inputOptions)
            print('What is the correct answer?')
            print('[a, b, c ,d]')
            correctAnswer = input('> ')
            #correctAnswer = correctAnswer.encode('utf-8')
            if correctAnswer not in opt:
                print('Error, the correct answer is not in the options...')
                doAdminCreateQuestionPool(localrowid, username)
            options = str(options)
            print(options)
            print(question)
            print(correctAnswer)
            #print(type(options))
            options = options.replace("'","")
            options = options.replace("[","")
            options = options.replace("]","")
            #print(options)
            try:
                DBcom.UserDB.create('questions','options','s',questionid,options)
                DBcom.UserDB.create('questions','correctAnswers','s',questionid,correctAnswer)
                DBcom.UserDB.create('questions', 'questions', 's', questionid, question)
                print('Question {} created successfully'.format(i))
            except OSError:
                print('Error creating question pool')
                print('Please try again')
                doAdminCreateQuestionPool(localrowid, username) 
        DBcom.UserDB.update('questions', 'NumberOfQ', 'q', '', '5', '', '')
        DBcom.UserDB.update('questions', 'NumberOfAtt', 'q', '', '3', '', '')
        
        print('+==================================+\n')
        print('\n')
        print('+==================================+\n')
    doAdminQuestions(localrowid, username)
    
def doAdminlistQuestionPool(localrowid, username):
    '''
    Purpose of this function is to allow the admin to list the question pool
    '''
    print('+==================================+\n')
    print(colors.fg.cyan, '\tList Question Pool', colors.reset)
    print('+==================================+\n')
    #Puts the questions pool in a list
    allQns = DBcom.UserDB.find('questions', 'questions', 'id', 're','raw','')
    allQnscnt = len(allQns)
    allQnsnum = len(allQns)
    Qnscnt, count, count2 = 1, 1, 1
    Module, Topic, resMod, resTopic, avaQns = [], [], [], [], []
    #asks the user to select Module and Topic and shows the questions
    print('\n')
    print('Which Module do you want to Edit?')
    print('Current Modules:\n')

    #CHOOSE MODULES
    for x in allQns:
        Module.append(x.split('_')[2])
    #remove duplicates in Module List 
    [resMod.append(x) for x in Module if x not in resMod]
    for mod in resMod:
        print('{}. {}'.format(count, mod.upper()))
        count += 1

    print('\n<ENTER> to go back')
    try:
        userChoiceMod = int(input('Please enter your choice: '))
        userChoiceMod = resMod[userChoiceMod-1]
    except ValueError:
        clearConsole()
        doAdminQuestions(localrowid, username)
        
    print('\n')
    #CHOOSE TOPIC
    print('Which Topic do you want to Edit?')
    print('Current Topics:\n')
    for x in allQns:
        if x.split('_')[2] == userChoiceMod:
            Topic.append(x.split('_')[3])

    #remove duplicates in Topic List
    [resTopic.append(x) for x in Topic if x not in resTopic]
    if len(resTopic) == 0:              
        clearConsole()                                #INSPECT FURTHER
        print('No Topics available')
        doAdminlistQuestionPool(localrowid, username)
    for top in resTopic:
        print('{}. {}'.format(count2, top.upper()))
        count2 += 1

    print('\n<ENTER> to go back')
    try:
        userChoiceTop = int(input('Please enter your choice: '))
        userChoiceTop = resTopic[userChoiceTop-1]
        print('\n')
    except ValueError:
        clearConsole()
        doAdminQuestions(localrowid, username)

    for allQnscnt in allQns:
        if str(userChoiceMod) == str(allQnscnt.split('_')[2]) and str(userChoiceTop) == str(allQnscnt.split('_')[3]):
            print("{}. Question: {}/ID: {}".format(Qnscnt,base64.b64decode(str((allQnscnt.split('_')[4]))).decode(),str(allQnscnt.split('_')[0])))
            avaQns.append(str(allQnscnt.split('_')[0]))
            Qnscnt += 1
    #prints all questions in the list with their unique id
    '''
    for allQnscnt in allQns:
        print("{}. Question: {}/ID: {}".format(Qnscnt,base64.b64decode(str((allQnscnt.split('_')[4]))).decode(),str(allQnscnt.split('_')[0])))
        Qnscnt = Qnscnt + 1
    '''
    print('+==================================+\n')
    print('Which question do you want to modify?: ')
    
    print('\n<ENTER> to go back')
    #prompts user input for doAdminModifyQuestion
    try:
        questionNumber = int(input('Please enter from [{}-{}]: '.format(1, len(avaQns))))
        clearConsole()
        doAdminModifyQuestion(localrowid, questionNumber, username, avaQns)
    except ValueError:
        clearConsole()
        doAdminQuestions(localrowid, username)

def doAdminModifyQuestion(localrowid, UserChoice, username, avaQns):
    '''
    Purpose of this function is to allow the admin to modify the questions chosen
    '''
    print('+==================================+\n')
    print(colors.fg.cyan, '\t  Modify Question', colors.reset)
    print('+==================================+\n')
    #declare variables
    questionid = ''
    optChoice = ['a', 'b', 'c', 'd']

    #checks if the question number is valid
    if UserChoice < 1 or UserChoice > int(len(avaQns)):
        clearConsole()
        print(colors.fg.red,'Invalid Question...', colors.reset)
        adminMenu(localrowid, username)
    else:
        #find the question id
        UserChoice -= 1

        #finds the question the user wants to modify
        question = DBcom.UserDB.find('questions', 'questions', 'id', 're','raw', '')
        for qn in question:
            if str(avaQns[UserChoice]) == str(qn).split('_')[0]:
                question = qn
        
        #finds the options the user wants to modify
        options = DBcom.UserDB.find('questions', 'options', 'id', 're','raw', '')
        for opt in options:
            if str(opt).split('_')[0] == str(question).split('_')[0]:
                options = opt

        #finds the correct answer the user wants to modify
        correctAnswer = DBcom.UserDB.find('questions', 'correctAnswers', 'id', 're','raw', '')
        for cor in correctAnswer:
            if str(cor).split('_')[0] == str(question).split('_')[0]:
                correctAnswer = cor

        #Displays the current question selected
        print('Question: {}'.format(base64.b64decode(str(question).split('_')[4]).decode()))
        #Displays the current options in the question selected
        print('Options: ')
        for i in range(1,5):
            print('{}) {}'.format(optChoice[i-1],base64.b64decode(str(options).split('_')[2]).decode().replace(' ', '').split(',')[i-1]))
        #Displays the current correct answer in the question selected
        print('Correct Answer: {}'.format(base64.b64decode(str(correctAnswer).split('_')[2]).decode()))
        #prompts the user to ask which category they want to modify
        print('+==================================+\n')
        print('What do you want to modify?')
        print('1. Question')
        print('2. Options')
        print('3. Correct Answer')
        print('\n<ENTER> to go back')
        print('+==================================+\n')
        try:
            modifyChoice = int(input('> '))
        except ValueError:
            clearConsole()
            adminMenu(localrowid, username)
        #if user wants to modify the question, it will prompt the user to enter the new question and then update the question
        if modifyChoice == 1:
            #displays the current question
            print('Question: {}'.format(base64.b64decode(question.split('_')[4]).decode()))
            questionid = question.split('_')[0]
            #prompts the user to enter the new question
            print('What is the new question?')
            newQuestion = input('> ')
            try:
                #updates the question
                modChoice = str(question).split('_')[2]
                topicChoice = str(question).split('_')[3]
                DBcom.UserDB.update('questions', 'questions', 'qn', questionid, newQuestion, modChoice, topicChoice)
                clearConsole()
                print('Question successfully modified')
                doAdminlistQuestionPool(localrowid, username)
            #catches any errors so the user can try again if there is an error
            except OSError:
                clearConsole()
                print(colors.fg.red,'Error updating question', colors.reset)
                print('Please try again')
                doAdminModifyQuestion(localrowid, UserChoice, username, avaQns)
        #if user wants to modify the options, it will prompt the user to enter the new options and then update the options
        elif modifyChoice == 2:
            #displays the current options
            print('These are the current options: ')
            print(base64.b64decode(options.split('_')[2]).decode())
            #prompts the user to enter the new options
            print('What are the new options?: ')
            questionid = question.split('_')[0]
            options = options.split('_')[2]
            options = []
            try:
                for i in range(1,5):
                    newOption = str(input('Enter the new option {}: '.format(i)))
                    options.append(newOption)
                    print(options)
            except ValueError:
                clearConsole()
                print(colors.fg.red,'Invalid input...', colors.reset)
                doAdminModifyQuestion(localrowid, UserChoice, username, avaQns)
            print(options)
            #updates the options
            try:
                clearConsole()
                DBcom.UserDB.update('questions', 'options', 's', questionid, str(options).replace("'","").replace("[","").replace("]",""), '', '')
                print('Option successfully modified')
                doAdminlistQuestionPool(localrowid, username)
            #catches any errors so the user can try again if there is an error
            except OSError:
                clearConsole()
                print(colors.fg.red,'Error updating options', colors.reset)
                print('Please try again')
                doAdminModifyQuestion(localrowid, UserChoice, username, avaQns)
        #if user wants to modify the correct answer, it will prompt the user to enter the new correct answer and then update the correct answer
        elif modifyChoice == 3:
            #displays the current correct answer
            print('Current Answer: {}'.format(base64.b64decode(correctAnswer.split('_')[2]).decode()))
            #prompts the user to enter the new correct answer
            print('What is the new correct answer?')
            questionid = question.split('_')[0]
            try:
                print('\n<ENTER> to go back')
                newCorrectAnswer = input('What is the correct answer?: ')
            except ValueError:
                clearConsole()
                doAdminModifyQuestion(localrowid, UserChoice, username, avaQns)
            #if the user input isnt (a,b,c,d) then it will prompt the user to try again
            if newCorrectAnswer not in opt:
                clearConsole()
                print(colors.fg.red,'Error, the correct answer is not in the options...', colors.reset)
                print('Answer not changed.')
                doAdminModifyQuestion(localrowid, UserChoice, username, avaQns)
            else:
                #updates the correct answer
                try:
                    clearConsole()
                    DBcom.UserDB.update('questions', 'correctAnswers', 's', questionid, newCorrectAnswer, '', '')
                    print('Correct answer successfully modified')
                    doAdminlistQuestionPool(localrowid, username)
                #catches any errors so the user can try again if there is an error
                except OSError:
                    clearConsole()
                    print('Error updating correct answer')
                    print('Please try again')
                    doAdminModifyQuestion(localrowid, UserChoice, username, avaQns)
    doAdminlistQuestionPool(localrowid, username)

#################################################################################
#                              takeQuiz + checkAnswer                           #
#################################################################################

def takeQuiz(localrowid, username):
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
        doAdminQuestions(localrowid, username)
    #Get the current time that the user started the quiz
    
    #Check if the user has enough attempts to take the quiz
    if int(attCount) <= 0:
        clearConsole()
        print(colors.fg.red,'You have no attempts left...', colors.reset)
        adminMenu(localrowid, username)
    
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
                takeQuiz(localrowid, username)
        #If the user input is 'e' the user will quit the quiz
        elif forward == 'e':
            clearConsole()
            print('Exiting Quiz...')
            doAdminQuestions(localrowid, username)
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
                    doAdminQuestions(localrowid, username)
                    print('+==================================+')
                    print('Thank you for taking the quiz.')
                    print('+==================================+')
                    state = False
                    doAdminQuestions(localrowid, username)
                takeQuiz(localrowid, username)
            elif retake == 'n':
                clearConsole()
                print('+==================================+')
                print('Thank you for taking the quiz.')
                print('+==================================+')
                adminMenu(localrowid, username)
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

# IF YOU WANT TO RUN THE ADMIN SCRIPT WITHIN THE ADMIN SCRIPT, UNCOMMENT THE FOLLOWING LINE
menu(localrowid=uuid.uuid4())