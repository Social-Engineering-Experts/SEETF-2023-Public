FROM python:3.7.9
WORKDIR /app

RUN useradd -m chall
RUN apt update
RUN apt install -y socat

COPY server.py .
COPY super-secret-no-touchy .
RUN chmod -R 555 /app
RUN chmod +r server.py
RUN chmod +r super-secret-no-touchy

USER chall

ENTRYPOINT socat tcp-l:1337,fork,reuseaddr exec:"python server.py"