FROM python:3.10-buster
WORKDIR /app

RUN apt-get update
RUN apt-get install -y socat

RUN pip install --upgrade pip
RUN pip install pycryptodome
RUN pip install qiskit

COPY flag.txt .
COPY chall.py .

ENTRYPOINT socat tcp-l:9999,fork,reuseaddr exec:"python chall.py"
