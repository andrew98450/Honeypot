FROM python:3.9.13-slim-buster AS python3

WORKDIR /

COPY . ./

RUN apt update

RUN apt install -y net-tools nano wget cmake make git unzip tar libemu-dev build-essential libssl-dev libffi-dev

RUN chmod +x start.sh

RUN git clone https://github.com/johnnykv/heralding.git

RUN pip3 install -r /heralding/requirements.txt

WORKDIR /heralding/

RUN python3 setup.py install

WORKDIR /

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

COPY --from=python3 . ./

ENTRYPOINT ["/bin/bash", "-c", "/start.sh"]

