FROM dinotools/dionaea:nightly AS dionaea

COPY . ./

RUN apt-get update

RUN apt-get install -y python3-pip net-tools nano expect

RUN pip3 install -r requirements.txt

FROM zerotier/zerotier:latest AS zerotier

COPY --from=dionaea . ./

RUN echo '/usr/local/sbin/entrypoint.sh &' >> /entrypoint.sh

RUN echo '/opt/dionaea/bin/dionaea -D' >> /entrypoint.sh

RUN echo 'python3 sniff.py' >> /entrypoint.sh

