FROM sagemath/sagemath:9.7
WORKDIR /app

RUN sudo apt-get update
RUN sudo apt-get install -y socat

COPY isogeny_maze.sage .

ENTRYPOINT socat tcp-l:5000,fork,reuseaddr exec:"sage isogeny_maze.sage"