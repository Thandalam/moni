from kafka import KafkaConsumer
from database import devicedata_collection
from json import loads
from dotenv import load_dotenv, find_dotenv
import os
import socket

load_dotenv(find_dotenv())

FORMAT='utf-8'

# fetching environment variable

bootstrapserver = (os.getenv('bootstrapserver'))

#kafka topic name
topicName = 'devicedata'


consumer = KafkaConsumer(topicName, bootstrap_servers = bootstrapserver,
                            group_id='devicedata_group', api_version=(0,11,5),
                            auto_offset_reset='earliest',
                            value_deserializer=lambda x:loads(x.decode(FORMAT)))
                            
# for every message in consumer, check if the value of the message is NONE....
# If NONE continue to look until the message.value is not NONE
# If message.value is not NONE - insert the message into the DB collection devicedata

for message in consumer:
    if(message.value!=None):
        data = message.value
        devicedata_collection.insert_one(data)
       

    else:
        continue


    



    
