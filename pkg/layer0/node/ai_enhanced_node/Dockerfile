# Use an official Python runtime as a parent image
FROM python:3.8-slim-buster

# Set the working directory in the container
WORKDIR /usr/src/app

# Install any necessary packages specified in requirements.txt
# Assuming that you have a requirements.txt file which lists all the packages that the node needs
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application's source code from your host to your image filesystem.
COPY . .

# Make port 8000 available for the app
EXPOSE 8000

# Define environment variable
ENV NAME AIEnhancedNode

# Run node.py when the container launches
# Assuming 'node.py' is the entry point of your Python application
CMD ["python", "node.py"]
