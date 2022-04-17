FROM python:3.9.12-slim AS python3

FROM zerotier/zerotier:latest AS zerotier

FROM zambhav/metasploitable2 AS metasploitable2

COPY --from=python3 . ./

COPY --from=zerotier . ./

RUN pip3 install -r requirements.txt