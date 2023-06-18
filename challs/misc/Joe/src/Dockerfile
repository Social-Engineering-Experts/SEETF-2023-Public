FROM ubuntu:22.04

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt install -y socat python3 && ln -sf /usr/bin/dash /bin/sh

RUN useradd -d /home/ctf/ -m -s /bin/bash ctf

COPY / /home/ctf/
WORKDIR /home/ctf
USER ctf

EXPOSE 1337
CMD ["socat", "tcp-l:1337,reuseaddr,fork", "EXEC:python3 ./server.py"]