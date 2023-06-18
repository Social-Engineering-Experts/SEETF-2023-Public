# Use a more specific version of Python, to reduce the chances of unexpected behavior
FROM python:3.9.16

# Install the necessary dependencies
RUN true \
    && mkdir /var/log/ctf /startup \
    && echo "deb http://ftp.debian.org/debian sid main" >> /etc/apt/sources.list \
    && apt update \
    && apt install -y libc6 libc6-dev xinetd tini \
    && rm -rf /var/cache/apt/archives \
    && useradd -m ctf \
    && chown -R ctf:ctf /tmp \
    && true

# Copy the startup scripts to the correct location
COPY eth-challenge-base/00-create-xinetd-service /startup
COPY eth-challenge-base/99-start-xinetd /startup
COPY eth-challenge-base/handler.sh /home/ctf/handler.sh
COPY eth-challenge-base/entrypoint.sh /entrypoint.sh

# Set the default command to run
ENTRYPOINT ["tini", "-g", "--"]
CMD ["/entrypoint.sh"]


# ================== ETH CHALLENGE BASE ==========================

COPY eth-challenge-base/requirements.txt /root

# Update Python3
RUN python3 -m pip install --upgrade pip && python3 -m pip install --upgrade setuptools && python3 -m pip install --upgrade wheel

RUN python3 -m pip install -r /root/requirements.txt 

RUN true \
    && curl -L https://foundry.paradigm.xyz | bash \
    && bash -c "source /root/.bashrc && foundryup" \
    && chmod 755 -R /root \
    && true

COPY eth-challenge-base/98-start-gunicorn /startup

COPY eth-challenge-base/eth_sandbox /usr/local/lib/python3.9/eth_sandbox

ENV PYTHONPATH /usr/local/lib/python3.9

RUN true \
    && cd /tmp \
    && /root/.foundry/bin/forge install @openzeppelin=OpenZeppelin/openzeppelin-contracts --no-git \
    && true

COPY eth-challenge-base/remappings.txt /tmp/remappings.txt
COPY eth-challenge-base/foundry.toml /tmp/foundry.toml

ARG SHARED_SECRET
ARG FLAG
ARG HTTP_HOST="127.0.0.1"
ARG HTTP_PORT="8545"
ARG PORT
ARG CHALLENGE_DIRECTORY
ARG CONTRACT_DEPLOY_ARGS=""
ARG CONTRACT_DEPLOY_VALUE="0"
ARG PLAYER_VALUE="10"

ENV PORT=${PORT}
ENV PUBLIC_IP=${HTTP_HOST}
ENV HTTP_PORT=${HTTP_PORT}
ENV SHARED_SECRET=${SHARED_SECRET}
ENV FLAG=${FLAG}
ENV CONTRACT_PATH="/home/ctf/compiled/Setup.sol/Setup.json"
ENV CONTRACT_DEPLOY_ARGS=${CONTRACT_DEPLOY_ARGS}
ENV CONTRACT_DEPLOY_VALUE=${CONTRACT_DEPLOY_VALUE}
ENV PLAYER_VALUE=${PLAYER_VALUE}

COPY ${CHALLENGE_DIRECTORY} /tmp/contracts/

RUN true \
    && cd /tmp \
    && /root/.foundry/bin/forge build --out /home/ctf/compiled \
    && rm -rf /tmp/contracts \
    && true
