FROM python:3.9.12-slim AS python3

COPY . ./

RUN pip3 install -r requirements.txt

FROM zerotier/zerotier:latest AS zerotier

COPY --from=python3 . ./

FROM zambhav/metasploitable2 AS metasploitable2

COPY --from=zerotier . ./

