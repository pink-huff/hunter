# Start with the Python base image
FROM python:alpine3.19

# Install build dependencies
RUN apk add --no-cache build-base libffi-dev openssl-dev

#WORKDIR /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

RUN pip install gunicorn

# If using Alpine, fix the package installation command
RUN apk add --no-cache nmap bind-tools

EXPOSE 5001

CMD gunicorn --workers 4 --chdir /app app:app --bind 0.0.0.0:5001