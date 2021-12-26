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
# DBcom is the database class that is used to access the filesystem commands.
import DBcom
# time is used to get the time taken to complete quiz.
import time
# uuid is used to generate a unique session id for the user.
import uuid
#############################################################################
#                                 menu                                      #
#############################################################################
#this is the main menu of the quiz app
#purpose of this menu is to provide the user with a menu to choose from
def menu(localrowid):
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
            login(localrowid)
        elif choice == 2:
            registerUser(localrowid, acl='00000')
        elif choice == 3:
            forgetPassword(localrowid)
        else:
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
def registerUser(rowid,acl = '00000'):
    username_pass = False
    email_pass = False
#acl = '00000'
#acl = '11111' #to create admin user
#regenerate rowid to ensure each record is unique
    localrowid = str(abs(hash(os.urandom(16)) % (10 ** 8)))
    print('+==================================+')
    print(colors.bold, colors.fg.cyan, '\t  Create User Menu', colors.reset)
    print('+==================================+')        
    print('Requirements:')
    print('1. Username must not contain special characters')
    print('3. Username/Password must be [4-20] characters')
    print('4. Password must contain at least one special character [@#$%^&+=]')
    print('5. Password must contain at least one upper and lower case letter')
    print('6. Password must contain at least one number [0-9]')
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
        menu(localrowid)
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
    #if all requirements are met then create the user account
    if username_pass == True and email_pass == True:
        try:
            DBcom.UserDB.create('users', 'acl', 's', localrowid, acl)
            DBcom.UserDB.create('users', 'username', 's', localrowid, username)
            DBcom.UserDB.create('users', 'password', 's', localrowid, password)
            DBcom.UserDB.create('users', 'otp', 's', localrowid, str(otp))
            DBcom.UserDB.create('users', 'email', 's', localrowid, email)
            print('+==================================+')
            print('Registration successful,\nreturn to the menu to login!\n')
            print('your email is {}, recovery OTP is {}'.format(email,otp))
            print('+==================================+\n')
            
        except ValueError:
            print('Error creating user')
            registerUser(rowid)
    else:
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
    print('+==================================+')
    print(colors.bold, colors.fg.cyan, '\t  Forget Password', colors.reset)
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
            # send the encoded password to the user via email without revealing the password
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
#                           Part of login()                                 #
#############################################################################

# Purpose of this function is to login the user.
# The user is asked to enter their username and password.
# The username and password are checked to see if they exist.
# If the username and password are valid and exist then the user is logged in.

def login(localrowid):
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
            password = str(input('Please enter your password: '))

        except ValueError:
            print(colors.bg.red, 'Please enter a valid password', colors.reset)
            login(localrowid)
        rowid = DBcom.UserDB.find('users', 'username', 'data','', 'id', username)
        username_pass = DBcom.UserDB.find('users', 'username', 'data','','bool', username)
        password_pass = DBcom.UserDB.find('users', 'password', 'data','','bool', password)
        userid = DBcom.UserDB.find('users', 'username', 'id','', 'id', username)
        #print(localrowid)
        #print(userid)
        #print(rowid)
        localrowid = rowid
        #print('username:[{}/{}]/password:[{}/{}]/loggedin_rowid:{}'.format(username,username_pass,password,password_pass,localrowid))
        try:
            #if the username and password are valid and exist then the user is logged in.
            #the logged in session will have a unique id according to the user logged in.
            if len(username_pass) > 0 and len(password_pass) > 0 and localrowid != '':
                print('+==================================+')
                print(colors.fg.green ,'Login successful {}/{}'.format(username,localrowid), colors.reset)
                print('+==================================+')
                doUserQuestions(localrowid, username)
            else :
                print(colors.fg.red, 'a. Incorrect username or password', colors.reset)
                login(localrowid)
        except ValueError:
            print(colors.fg.red, 'b. Incorrect username or password', colors.reset)
            login(localrowid)

    except ValueError:
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
        #Finds out the number of attempts the admin has set for the quiz
        attCount = DBcom.UserDB.find('questions', 'NumberOfAtt', 'id', 're', 'raw', '')
        attCount = attCount[0].split('_')[2]
        takeQuiz(localrowid, username, count = attCount)
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
    print('+==================================+\n')
    print(colors.fg.cyan , '\tUser Results Menu...', colors.reset)
    print('UserID: {}'.format(username))
    print('+==================================+\n')
    '''
    try:
        userChoice = int(input('> '))
    except ValueError:
        doUserQuestions(localrowid, username)
    '''
    i = 1
    usercnt = 0
    localrowid = localrowid[0]
    #Store the results of the user in a list
    userList = DBcom.UserDB.find('users', 'results', 'id','re','raw', '')
    #find the correct user's results based on the unique userid
    for results in userList:
        if localrowid == results.split('_')[0]:
            date = results.split('_')[2]
            date = str(base64.b64decode(date).decode('utf-8'))
            userResult = results.split('_')[3]
            print('{}. {} - {}%'.format(i, date, userResult))
            i += 1
            usercnt = 1
    #if the user has no results then tell them that they have no results
    if usercnt == 0:
        print('There are no results for this user...\n')
        doUserQuestions(localrowid, username)
    doUserQuestions(localrowid, username)

#################################################################################
#                              takeQuiz + checkAnswer                           #
#################################################################################
def takeQuiz(localrowid, username, count):
    print('+==================================+\n')
    print(colors.fg.cyan, '\t     Take Quiz', colors.reset)
    print('+==================================+\n')
    #list the question pool
    resultList = []
    #declaring the variables
    allOptnum = ''
    Opt = ['a', 'b', 'c', 'd']
    state = True
    forward = ''
    question = ''
    Qnscnt = 0
    Qnsid = 1
    #Finds the number of questions in the quiz that the admin has set
    Qnsno = DBcom.UserDB.find('questions', 'NumberOfQ', 'id', 're','raw','')
    Qnsno = int(Qnsno[0].split('_')[2])
    #Finds all the questions in the question pool and stores them in a list
    #note: the questions in this list are encoded
    allQns = DBcom.UserDB.find('questions', 'questions', 'id','re', 'raw','')
    #Finds all the options in the question pool and stores them in a list
    alloptions = DBcom.UserDB.find('questions', 'options', 'id', 're','raw','')
    #Finds the number of attempts the admin has set for the quiz
    attCount = DBcom.UserDB.find('questions', 'NumberOfAtt', 'id', 're', 'raw', '')
    attCount = attCount[0].split('_')[2]
    attCount = int(attCount)
    #If the number of questions in question pool is less then the number of questons the admin set then the admin will be told that there are not enough questions in the question pool
    allQnscnt = len(allQns)
    if int(Qnsno) > int(allQnscnt):
        print('Error, there are not enough questions in the pool...')
        print('Please ask the admin to add more questions...')
        doUserQuestions(localrowid, username)
    #Get the current time that the user started the quiz
    currentTime = time.time()
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
                resultList.pop(Qnscnt)
                resultList.pop(Qnscnt-1)
            except IndexError:
                print('Error, you cannot go back on the first question')
                Qnscnt += 1
                Qnsid += 1
        #If the user input is 'e' the user will quit the quiz
        elif forward == 'e':
            print('Exiting Quiz...')
            doUserQuestions(localrowid, username)
        else:
            pass
        #The question displayed will be according to the index in the question List
        try:
            question = allQns[Qnscnt]
        except IndexError:
            pass
        #lets the user know what question they are on
        print("QuestionID: {}/{}".format(Qnsid, Qnsno))
        #prints the question from the question list decoded
        print("Question:\n{}".format(base64.b64decode(str(question.split('_')[2])).decode('utf-8')))
        #prints the options from the option list decoded according to the question's unique id
        for i in range(0, Qnsno):
            allOptnum = alloptions[i]
            if question.split('_')[0] == allOptnum.split('_')[0]:
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
                            print('Answer saved.')
                        #if the user input is not in the form of (a,b,c,d) then the user will be told that they have not entered the correct answer
                        else:
                            print('Answer not in options')
                            print('Answer not saved.\n')
                            takeQuiz(localrowid, username, count)
                        print(len(resultList))
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
            if Qnsid == Qnsno+1:
                print('You have reached the end of the quiz')
                print('+==================================+')
                print('Summary page:')
                #prints the summary page consisting of questions asked and the user's answers
                for i in range(0, len(resultList)):
                    try:
                        print('Question: {}\nAnswer:{}'.format(base64.b64decode(str(allQns[i].split('_')[2])).decode('utf-8'), resultList[i]))
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
                    takeQuiz(localrowid, username, count)
                if submit == 'y':
                    state = False
                    print(attCount)
                    checkAnswer(localrowid, username, resultList, Qnsno, allQns, attCount, count, currentTime)
                else:
                    Qnscnt -= 1
                    Qnsid -= 1
                    resultList.pop(Qnscnt)
                    resultList.pop(Qnscnt-1)

def checkAnswer(localrowid, username, resultList, Qnsno, allQns, attCount, count, currentTime):
    print('+==================================+\n')
    print(colors.fg.cyan, '\tChecking Answer...', colors.reset)
    print('+==================================+\n')
    localrowid = localrowid[0]
    #declares the variables
    QnsList = []
    correctNum = 0
    score = 0
    state = True
    Tscore = Qnsno*2
    #Finds the correct answer for each question
    modelAnsList = DBcom.UserDB.find('questions', 'correctAnswers', 'id', 're','raw','')
    #Finds the time taken for the user to end the quiz: endTime - startTime
    elapsedTime = time.time() - currentTime
    elapsedTime = round(elapsedTime, 2)
    print('User: {}'.format(username))
    #Finds the number of questions answered correctly and incorrectly
    for i in range(0, Qnsno):
        if base64.b64decode(modelAnsList[i].split('_')[2]).decode('utf-8') == resultList[i]:
            print('Question {}. Correct!'.format(i+1))
            correctNum = correctNum + 1
            score+=2
        else:
            print('Question {}. Incorrect!'.format(i+1))
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
    DBcom.UserDB.createQn('users', 'results', 's', localrowid, percnt)
    #write percnt and username to results.csv
    #find the total number of questions
    #find the number of questions answered correctly
    #write the percentage to the user's results.csv
    #write the time taken to the user's results.csv
    for i in range(0, Qnsno):
        Qns = allQns[i]
        Ans = resultList[i]
        Model = modelAnsList[i]
        #As the questions are in base64 format, we need to decode them before we can use them
        QnsList.append(base64.b64decode(Qns.split('_')[2]).decode('utf-8'))
        QnsList.append(Ans)
        QnsList.append(base64.b64decode(Model.split('_')[2]).decode('utf-8'))
    QnsList.append(str(elapsedTime)+' seconds')
    #As a the values are in a list, we need to convert them to a string and replace all unnessecary characters before storing them in the csv file
    QnsList = str(QnsList).replace('[', '').replace(']', '').replace("'", '')
    open('results.csv', 'a').write('\n{},{},{},{}'.format(username, str(QnsList.split(',')).replace('[', '').replace(']', '').replace("'", '').replace(' ', ''), str(percnt)+'%', datetime.datetime.now()))
    #ask if user wants to retake quiz
    while state == True:
        print('Do you want to retake the quiz?')
        #print('count> {}'.format(count))
        #displays the number of tries the user has left to attempt the quiz
        count = int(count) - 1 
        print('[{}/{}] attempts left.'.format(count, attCount))
        print('[y]es or [n]o')
        try:
            retake = str(input('Please enter your choice: ')).lower()
            if retake == 'y':
                #if the user wants to retake the quiz then the quiz will be reset
                #if the count is equal to 0 then the user will be told that they have run out of attempts
                if count == 0:
                    print(colors.bg.red, 'You have no more attempts left.', colors.reset)
                    doUserQuestions(localrowid, username)
                    print('+==================================+')
                    print('Thank you for taking the quiz.')
                    print('+==================================+')
                    state = False
                    doUserQuestions(localrowid, username)
                takeQuiz(localrowid, username, count)
            else:
                print('+==================================+')
                print('Thank you for taking the quiz.')
                print('+==================================+')
                doUserQuestions(localrowid, username)
                state = False
        except ValueError:
            print('Invalid input...')
            doUserQuestions(localrowid, username)

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
#menu(localrowid = uuid.uuid4())
