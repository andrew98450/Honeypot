FROM ctfrayz/dvwarepo:dvwa AS dvwa

COPY . ./

RUN apt update

RUN apt install -y net-tools nano wget cmake make git tar libx86emu-dev libffi-dev libgdbm-dev libsqlite3-dev libssl-dev zlib1g-dev iptables

RUN chmod +x start.sh

RUN wget https://www.python.org/ftp/python/3.9.13/Python-3.9.13.tgz

RUN tar xzf Python-3.9.13.tgz

RUN ./Python-3.9.13/configure

RUN make

RUN make install

RUN rm -fr /Python-3.9.13/

RUN rm Python-3.9.13.tgz

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

FROM zerotier/zerotier:1.6.6 AS zerotier

COPY --from=dvwa . ./

ENTRYPOINT ["/bin/bash", "-c", "/start.sh"]

