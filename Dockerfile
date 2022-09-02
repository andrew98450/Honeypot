FROM python:3.9.13-slim-buster AS python3

COPY . ./

RUN apt update

RUN apt install -y libemu-dev net-tools nano gcc wget tar iptables

RUN pip3 install -r requirements.txt

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

FROM zerotier/zerotier:1.8.7 AS zerotier

COPY --from=python3 . ./

EXPOSE 21 22 23 25 53/udp 80 111 139 445 512 513 514 2049 2121 3306 5432 5900 6000

ENTRYPOINT ["/bin/bash", "-c", "./start.sh"]