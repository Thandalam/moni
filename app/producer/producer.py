from kafka.producer import KafkaProducer
import socket
from json import dumps
import json
import time
from dotenv import load_dotenv, find_dotenv
import os

load_dotenv(find_dotenv())

FORMAT = 'utf-8'

#fetching port from env variable 
PORT = int(os.getenv('PORT'))

#kafka server
bootstrapserver = (os.getenv('bootstrapserver'))     


#Configuring server, port for the host
HOST_SERVER = socket.gethostbyname('socket')
# HOST_SERVER = socket.gethostbyname('localhost')


ADDR = (HOST_SERVER,PORT)

#Connect to the socket server to establish connection
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

#Kafka topic name
topicName = 'devicedata'


producer = KafkaProducer(bootstrap_servers = bootstrapserver, api_version=(0,11,5),
              value_serializer=lambda x: dumps(x, indent=1).encode(FORMAT))


while True:
    data = client.recv(1024).decode(FORMAT)
    datatoconsumer = json.loads(data.encode(FORMAT))
    time.sleep(5)
    producer.send(topicName, value=datatoconsumer)






   


        