# Use file system to store rows of data.
# Stores data in the filenames in rows and columns.
# Provides high concurrency and low latency only limited by the file system.
# does not have read/write locks.
# usage:
# create - create a new table with a column and row data returns unique rowid
# find - find a matching data in table/column returns rowid
# read - read data from table/column/rowid returns data
# update - update data in table/column/rowid returns true/false
# delete - delete data from table/column/rowid returns true/false
#################################################################################
#                               Import Libraries                                #
#################################################################################
# datetime for date and time
from datetime import datetime
# os is used to navigate the directory, create files, delete files, update files, etc.
import os
# base64 for encoding and decoding
import base64
# glob for file and directory search
import glob
# shutil for file and directory deletion
import shutil
# re for regular expression operations
import re
#################################################################################
#                               CRUD Operations                                 #
#################################################################################
class UserDB():
    def create(tableName, colName, colType, localrowid, data):
        #gets the path to the table and column
        path = ('jsonPython/db/' + tableName + '/' + colName)
        #creates the path if it does not exist
        os.makedirs(path, exist_ok=True)
        #creates the file name
        #if colType == 's':
        #the data will be encoded to base64
        filename = ''
        if colType == 's':
            data = data.encode('utf-8')
            data = str(base64.b64encode(data))
            filename = str(localrowid) + '_' + str(colType) + '_' + str(data)[2:-1]
        #if colType is not 's'
        #the data will be the same as the data, not encoded
        if colType == 'r':
            filename = str(localrowid) + '_' + str(colType) + '_' + str(data)[2:-1]
        if colType == 'result':
            
            
            filename = str(localrowid) + '_' + str(colType) + '_' + str(data)
        #creates the file with the file name and data
        #note: the data is stored in the filename and not in the file itself
        with open(path+'/'+filename, 'w+') as f:
            #f.write(date+'_'+str(data))
            f.write(str(data))
        return localrowid
    
    def createQn(tableName, colName, colType, localrowid, data):
        #gets the path to the table and column
        path = ('jsonPython/db/' + tableName + '/' + colName)
        filename = ''
        #creates the path if it does not exist
        os.makedirs(path, exist_ok=True)
        #creates the file name
        #if colType == 's':
        #the date and data will be encoded to base64
        if colType == 's':
            date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            date = date.encode('utf-8')
            date = str(base64.b64encode(date))
            data = str(date) + '_' + str(data)
            filename = str(localrowid) + '_' + str(colType) + '_' + str(data)[2:]
        elif colType == 'r':
            date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            date = date.encode('utf-8')
            date = str(base64.b64encode(date))

            data = data.encode('utf-8')
            data = str(base64.b64encode(data))

            data = str(date) + '_' + str(data)[2:-1]
            filename = str(localrowid) + '_' + str(colType) + '_' + str(data)[2:]
        else:
            filename = str(localrowid) + '_' + str(colType) + '_' + str(data)
        #creates the file with the file name and data
        with open(path+'/'+filename, 'w+') as f:
            f.write(str(data))
        return localrowid

    def createMod(tableName, colName, colType, module, topic, localrowid, data):
        #gets the path to the table and column
        path = ('jsonPython/db/' + tableName + '/' + colName)
        filename = ''
        #creates the path if it does not exist
        os.makedirs(path, exist_ok=True)
        #creates the file name
        #if colType == 's':
        #the date and data will be encoded to base64
        if colType == 'qn':
            data = data.encode('utf-8')
            data = str(base64.b64encode(data))
            filename = str(localrowid) + '_' + str(colType) + '_' + str(module) + '_' + str(topic) + '_' + str(data)[2:-1]
        #creates the file with the file name and data
        with open(path+'/'+filename, 'w+') as f:
            f.write(str(data))
        return localrowid

    def find(tableName, colName, searchPart, searchMethod, returnType, data):
        results = []
        # if the searchPart is 'id', the data will be remain the same
        if searchPart == 'id':
            data = str(data)
        else:
            #if the searchPart is not 'id', the data will be encoded
            data = str(data).encode('utf-8')
        dir_name = 'jsonPython/db/'+tableName+'/' + colName
        #using glob, the program will search the directory for the file name
        file_list = sorted(filter(os.path.isfile, glob.glob(dir_name + "/*")),key=os.path.getmtime)

        for files in file_list:
            #gets the file name and stores it in the filename variable
            file = os.path.basename(files)
            #if the searchPart is 'data', the data will be decoded and stored in the list
            if searchPart == 'data':
                file_data = str(file.split('_')[2])
                file_data = base64.b64decode(file_data + '==')
            else:
                #if the searchPart is not 'data', the data will be the the rowid
                file_data = str(file.split('_')[0])
            #if the searchMethod is 're', the data will be compared using regular expression
            #3 returnTypes, "bool", "arr" and "id"
            #bool returns true if the data is found
            #arr returns the data in an list
            #id returns the rowid
            if searchMethod == 're':
                if bool(re.match(str(data).replace(" ", ""),str(file_data).replace(" ", ""))):
                    if returnType == 'bool':
                        results.append(True)
                        
                    elif returnType == 'arr':
                        results.append(str(base64.b64decode(file.split('_')[2]))[2:-1])
                    elif returnType == 'id':
                        results.append(file.split('_')[0])
                    else:
                        results.append(file)
            #if the searchMethod is not 're', the data will be compared using '=='
            #3 returnTypes, "bool", "arr" and "id"
            #bool returns true if the data is found
            #arr returns the data in an list
            #id returns the rowid
            else:    
                if str(data) == str(file_data):
                    if returnType == 'bool':
                        results.append(True)
                    elif returnType == 'arr':
                        results.append(str(base64.b64decode(file.split('_')[2]))[2:-1])
                    elif returnType == 'id':
                        results.append(file.split('_')[0])
                    else:
                        results.append(file)
        
        return results

    def update(tableName, colName, colType, localrowid, data, modChoice, topicChoice):
        #gets the path to the table and column
        path = ('jsonPython/db/' + tableName + '/' + colName)
        for root, dirs, files in os.walk(path):
            for file in files:
                #if the row id given matches the row id in the specific filename, the filename will be updated
                if colType == 's':
                    if file.split('_')[0] == str(localrowid):
                        #if the data is not encoded, the data will be encoded if the colType is 's'
                        data = data.encode('utf-8')
                        data = base64.b64encode(data)
                        data = str(data)[2:-1]
                        os.remove(path +'/'+ file)
                        with open(path +'/'+ str(localrowid) + '_' + colType + '_' + str(data), 'w+') as f:
                            f.write(str(data))
                        return data   
                elif colType == 'qn':
                    if file.split('_')[0] == str(localrowid):
                        #if the data is not encoded, the data will be encoded if the colType is 's'
                        data = data.encode('utf-8')
                        data = base64.b64encode(data)
                        data = str(data)[2:-1]
                        os.remove(path +'/'+ file)
                        with open(path +'/'+ str(localrowid) + '_' + colType + '_' + str(modChoice) + '_' + str(topicChoice) + '_' + str(data), 'w+') as f:
                            f.write(str(data))
                        return data  
                else:
                    if file.split('_')[0] == str(localrowid):
                        os.remove(path +'/'+ file)
                        with open(path +'/'+ str(localrowid) + '_' + colType + '_' + str(data), 'w+') as f:
                            f.write(str(data))
                        return data  

    def delete(tableName, colName):
        #gets the path to the table and column
        path = ('jsonPython/db/' + tableName + '/' + colName)
        #deletes all files in the directory(column) 
        if os.path.exists(path):
            shutil.rmtree(path)
            print('Deleted\t' + path + '\tsuccessfully')
            return True
        else:
            #if the directory does not exist, the delete function will return false
            print('This table does not exist...')
            return False
        
    def deleteUser(tableName, colName, localrowid):
        #returns the user id of the user that is being deleted
        find_result = UserDB.find(tableName, colName, 'id','q','raw', localrowid)
        #gets the path to the table and column and row thats being deleted
        path = ('jsonPython/db/' + tableName + '/' + colName + '/' + find_result[0])
        #deletes the file
        os.remove(path)