import socket
import errno
import json
import time
import random
from dotenv import load_dotenv, find_dotenv
import os
import sys


load_dotenv(find_dotenv(), override=True)

#fetching port from env variable 
PORT = int(os.getenv('PORT'))
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = 'DISCONNECT'

#Configuring the server, port for host
try:
    HOST_SERVER = socket.gethostbyname('socket')
    # HOST_SERVER = socket.gethostbyname('localhost')

    ADDR = (HOST_SERVER, PORT)

except socket.gaierror:
    print("Error resolving the host!!")
    exit()
    
# Creating the socket server & binding it to the host server configured earlier
# 2 connections can be kept waiting at any time.. 3rd connection will be refused.
try:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)    
    server.listen(2)    
    conn, addr = server.accept()

except socket.error as err:
    print("Socket creation failed with error %s" %(err))


connected = True
while connected:
    try:       
            for i in range(30):
                route = ['Newyork,USA','Chennai, India','Bengaluru, India','London,UK']
                routefrom = random.choice(route)
                routeto = random.choice(route)
                if (routefrom!=routeto):
                    data = {
                        "Device_ID": random.randint(11565300,11565310),
                        "Battery_Level":round(random.uniform(2.00,5.00),2),
                        "First_Sensor_temperature":round(random.uniform(10,40.0),1),
                        "Route_From":routefrom,
                        "Route_To":routeto
                        }
                    devicedata = (json.dumps(data, indent=1)).encode(FORMAT)
                    conn.send(devicedata)
                    print(devicedata)
                    time.sleep(20)
                else:
                    pass

                
              


# exception incase of Broken PIPE error.
    except IOError as e:
            if e.errno == errno.EPIPE:
                exit()

