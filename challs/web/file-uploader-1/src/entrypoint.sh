#!/bin/bash
python3 app.py &

# poor man's crontab
while true; do rm -rf /home/userr/app/static/{*,.*}; echo "[+] Cleaned up files"; sleep 60; done