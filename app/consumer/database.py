from dotenv import load_dotenv, find_dotenv
from pymongo import MongoClient
import os

load_dotenv(find_dotenv(), override=True)

#fetching database username & password
mongourl = os.getenv('MONGO_URI')


#client for mongodb connection
client = MongoClient(mongourl)
# print("mongodb+srv://%s:%s@%s.e7jd0c9.mongodb.net/?retryWrites=true&w=majority"%(username,password,dbname))
db =client. scmxpertlite

#Database collections
devicedata_collection = db['Device_data']
