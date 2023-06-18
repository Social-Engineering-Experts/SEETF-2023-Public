FROM python:slim AS app
RUN pip install --no-cache-dir pycryptodome

FROM pwn.red/jail
COPY --from=app / /srv
COPY romeo_and_juliet.py /srv/app/run
RUN chmod +x /srv/app/run
ENV JAIL_TIME=120 JAIL_ENV_FLAG=SEE{O_Franklin-Reiter,_Franklin-Reiter,_wherefore_art_thou_Franklin-Reiter?_d0df1731bfea05134a97fbb244a85547}
