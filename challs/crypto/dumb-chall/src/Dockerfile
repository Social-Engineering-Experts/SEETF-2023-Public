FROM python:3.11-alpine
WORKDIR /app

RUN apk add --no-cache socat
RUN pip install pycryptodome

COPY main.py .
COPY secret.py .

ENTRYPOINT socat tcp-l:1337,fork,reuseaddr exec:"python main.py"
