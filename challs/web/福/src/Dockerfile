FROM python:3.9

RUN python3 -m pip install flask z3-solver itsdangerous waitress


WORKDIR /app

COPY . /app

RUN echo "SEE{H0w_f0rtun4T3_Y3t_An0theR__FL4sk_UnSigN_}" > /app/flag.txt

RUN useradd 福

USER 福

CMD ["python3", "app.py"]
