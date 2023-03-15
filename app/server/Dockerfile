
# # Base image
# FROM python:3.8.10


# # Set the working directory
# WORKDIR ./socket
# # Copy the socket server file to the container
# COPY . /socket

# RUN pip install python-dotenv

# # Expose the port on which the socket server will run
# EXPOSE 12345

# # Run the socket server
# CMD ["python3", "server.py"]
FROM python:3.9
WORKDIR /app/socket
COPY . .
RUN pip install python-dotenv
CMD ["python","server.py"]



