'''
;==========================================
; Title: create Server Using Socket and press Enter to shutdown the server python socket? (Threading, Socket, Time, Keyboard, Server).
; Author: codenaive Santosh Kumar   
; Date:   18 Dec 2021
; Programming Language: Python
;==========================================
'''	
from socket import *
from time import ctime
import threading
import keyboard
import user
import uuid

HOST = "localhost"
PORT = 23
ADDRESS= (HOST,PORT)
server= socket(AF_INET,SOCK_STREAM)
rowid = hash(uuid.uuid4())
server.bind(ADDRESS)
server.listen(5)


def shutdown_server():
    server.close()							
    print("Server is shutdown")

def server_client_connection():
    while True:
        try:
            print("waiting for connection...")
            (client,address) = server.accept()
            print("... connected from : ",address)
            client.send(bytes(ctime()+user.menu(rowid),encoding="ascii"))
            client.close();
        except:
            server.close()
            print("Server Shutdown...");
            break

def close_the_connection():
        while True:            
            if keyboard.is_pressed('q'):
                t3=threading.Thread(target=shutdown_server()).start()
                break

try:
    t1=threading.Thread(target= server_client_connection).start()
    t2=threading.Thread(target= close_the_connection).start()
except:
    print("Error: unable to start thread")	

