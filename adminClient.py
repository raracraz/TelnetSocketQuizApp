import socket, sys
import admin3 as admin
import uuid
import base64


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('localhost', 23))

def downloadFile(filename):
    '''
    Purpose of this function is to download the files from the server to the client
    '''
    #get the file from the server
    file = s.recv(1024)
    #decode the file
    file = base64.b64decode(file)
    #open the file to write
    with open(filename, 'wb') as f:
        f.write(file)
    #print the file downloaded
    print('\nFile downloaded successfully.\n')

#Function to upload the files to the server
def uploadFile(filename, localrowid):
    '''
    Purpose of this function is to upload the files to the server
    '''
    #open the file to read
    with open(filename, 'rb') as f:
        #read the file
        file = f.read()
    #encode the file
    file = base64.b64encode(file)
    #send the file to the server
    s.send(file)
    #print the file uploaded
    print('\nFile uploaded successfully.\n')

while True:
    admin.menu(localrowid=uuid.uuid4(), )

    msg = input("msg to send ['q' to quit]=> ")    
    obuf = msg.encode() # convert msg string to bytes
    ret=s.send(obuf)
    #print("{} byte(s) have sent".format(ret))

    if (msg == 'q'):
        s.close()
        break  
    else:
        ibuf = s.recv(255)
    if len(ibuf) > 0:
        print(ibuf.decode())
    else:
        print("The connection has dropped")
        break
print("Bye Bye")