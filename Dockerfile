FROM python:3.9.13-slim-buster AS python3

COPY . ./

RUN apt update

RUN apt install -y \ 
    build-essential \   
    cmake \
    check \
    cython3 \
    libcurl4-openssl-dev \
    libemu-dev \
    libev-dev \
    libglib2.0-dev \
    libloudmouth1-dev \
    libnetfilter-queue-dev \
    libnl-3-dev \
    libpcap-dev \
    libssl-dev \
    libtool \
    libudns-dev \
    python3 \
    python3-dev \
    python3-bson \
    python3-yaml \
    python3-boto3 \
    fonts-liberation \
    tar unzip \
    libffi-dev \
    wget \
    make \
    git nano net-tools

RUN chmod +x start.sh

RUN git clone https://github.com/DinoTools/dionaea.git

RUN mkdir /dionaea/build/

WORKDIR /dionaea/build/

RUN cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/dionaea ..

RUN make

RUN make install

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

