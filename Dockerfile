ARG PYVERSION=3.9.19-bullseye

FROM python:${PYVERSION} AS dev

WORKDIR /app

COPY requirements.txt /app/

RUN apt-get update \
    && apt-get install -q -y \
    jq \
    && apt-get clean

RUN pip install -r requirements.txt

FROM dev as prod

COPY ./ /app/


