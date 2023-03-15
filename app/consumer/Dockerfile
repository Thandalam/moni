
# # Base image
# FROM python:3.8.10

# # Set the working directory
# WORKDIR /app/consumer

# # Copy the consumer server file to the container
# COPY . /app/consumer

# RUN pip install -r requirements.txt 

# CMD python -u consumer.py
FROM python:3.9
WORKDIR /app/consumer
RUN pip install pymongo[srv]  kafka-python python-dotenv==0.19.2
COPY . .
# RUN pip install python-dotenv
# RUN pip install pymongo
CMD ["python3","consumer.py"]
