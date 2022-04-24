FROM python:3.9.12-slim AS python3

COPY . ./

RUN pip3 install -r requirements.txt

FROM zerotier/zerotier:latest AS zerotier

COPY --from=python3 . ./

FROM cowrie/cowrie:latest AS cowrie
FROM dinotools/dionaea:latest AS dionaea

COPY --from=cowrie . ./
COPY --from=zerotier . ./

CMD [ "python3", "sniff.py" ]