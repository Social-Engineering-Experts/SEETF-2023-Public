FROM python:3.9-slim-buster

# Add user 
RUN addgroup --gid 10101 userr && \
adduser --disabled-password --uid 1010 --gecos "" --ingroup userr userr

# Set the working directory to /userr/app
WORKDIR /home/userr/app
RUN chown -R userr:userr /home/userr/app

# Copy the current directory contents into the container at /userr/app
COPY app.py flag.txt requirements.txt /home/userr/app/
COPY templates /home/userr/app/templates

# Install any needed packages specified in requirements.txt
RUN pip install --trusted-host pypi.python.org -r requirements.txt

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Define environment variable
ENV secret_key "c3d732ad-b6fe-4850-852b-f8d47a34d558"

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

# Run app.py as userr
USER userr
CMD ["/entrypoint.sh"]