FROM dinotools/dionaea:nightly AS dionaea

COPY . ./

RUN chmod +x ./start.sh
RUN chmod +x ./start.exp

RUN apt-get update

RUN apt-get install -y python3-pip net-tools nano expect

RUN pip3 install -r requirements.txt

FROM zerotier/zerotier:latest AS zerotier

COPY --from=dionaea . ./

CMD ["./start.exp"]

