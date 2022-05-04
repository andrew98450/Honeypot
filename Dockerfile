FROM dinotools/dionaea:nightly AS dionaea

COPY . ./

RUN chmod +x ./start.sh

RUN apt-get update

RUN apt-get install -y python3-pip net-tools nano

RUN pip3 install -r requirements.txt

FROM zerotier/zerotier:latest AS zerotier

HEALTHCHECK --interval=5s --timeout=3s CMD 

COPY --from=dionaea . ./

ENTRYPOINT ["/bin/bash", "-c"]

CMD ["./start.sh"]
