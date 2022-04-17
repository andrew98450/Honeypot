FROM python:3.9.12-slim AS python3

COPY . ./

RUN pip3 install -r requirements.txt

FROM zerotier/zerotier:latest AS zerotier

COPY --from=python3 . ./
COPY --from=zerotier . ./

FROM edurange2/metasploitable3 AS metasploitable3

CMD [ "/bin/bash" ]

