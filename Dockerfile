FROM h0pp/bwapp:latest AS bwapp

WORKDIR /

COPY . ./

ENV VERSION 1.9

RUN apt update

RUN apt install -y net-tools nano wget cmake make git unzip tar libemu-dev libffi-dev libssl-dev \
 libgdbm-dev libsqlite3-dev zlib1g-dev iptables \
 python3 libpython3-dev python3-pip \
 apache2 mariadb-server php php-mysql php-gd libapache2-mod-php

RUN chmod +x start.sh

RUN wget https://lcamtuf.coredump.cx/p0f3/releases/old/2.x/p0f-2.0.8.tgz

RUN tar xvf /p0f-2.0.8.tgz

RUN mkdir /opt/local

RUN mv /p0f/p0f.fp /opt/local

RUN mv /p0f/p0fa.fp /opt/local

RUN mv /p0f/p0fr.fp /opt/local

RUN mv /p0f/p0fo.fp /opt/local

RUN rm -fr /p0f/

RUN rm p0f-2.0.8.tgz

RUN pip3 install -r requirements.txt

FROM zerotier/zerotier:1.8.7 AS zerotier

COPY --from=bwapp . ./

EXPOSE 80 3306

ENTRYPOINT ["/bin/bash", "-c", "/start.sh"]

