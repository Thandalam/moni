FROM python:3.8.10

# Copy the requirements file to the container
COPY . /scmxpertlite/scmxpert/app

# # Copy the requirements file to the container
COPY ./requirements.txt /scmxpertlite/scmxpert/app/requirements.txt

# Set the working directory to /app
WORKDIR /scmxpertlite/scmxpert/app

# Install the dependencies
RUN apt-get update && apt-get install -y python3-pip && pip3 install -r requirements.txt

# Expose port 80 for the API
EXPOSE 8000

# Run the app
CMD [ "uvicorn", "main:APP", "--reload", "--host=0.0.0.0","--port= 8000"]