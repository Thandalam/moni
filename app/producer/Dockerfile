
FROM python:3.9
WORKDIR /app/producer
RUN pip install  kafka-python
RUN pip install python-dotenv
COPY  . .
CMD ["python3","producer.py"]

