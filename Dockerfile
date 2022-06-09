FROM dinotools/dionaea:nightly AS dionaea

COPY . ./

RUN chmod +x ./start.sh

RUN apt-get update

RUN apt-get install -y net-tools nano

FROM python:3.9.8-alpine3.14 as python3

RUN pip3 install -r requirements.txt

COPY --from=dionaea . ./

FROM zerotier/zerotier:latest AS zerotier

COPY --from=python3 . ./

HEALTHCHECK --interval=5s --timeout=3s CMD /usr/local/sbin/entrypoint.sh &

ENTRYPOINT ["/bin/bash", "-c"]

CMD ["./start.sh"]
