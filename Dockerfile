FROM dinotools/dionaea:latest AS dionaea

COPY . ./

RUN chmod +x start.sh

RUN apt-get update

RUN apt-get install -y net-tools nano wget cmake make build-essential libssl-dev zlib1g-dev \
       libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm \
       libncurses5-dev libncursesw5-dev xz-utils tk-dev libffi-dev

RUN wget https://lcamtuf.coredump.cx/p0f3/releases/old/2.x/p0f-2.0.8.tgz

RUN tar xvf p0f-2.0.8.tgz

RUN mkdir /opt/local

RUN mv ./p0f/p0f.fp /opt/local

RUN mv ./p0f/p0fa.fp /opt/local

RUN mv ./p0f/p0fr.fp /opt/local

RUN mv ./p0f/p0fo.fp /opt/local

RUN rm -fr ./p0f/

RUN wget https://www.python.org/ftp/python/3.9.13/Python-3.9.13.tar.xz

RUN tar xvf Python-3.9.13.tar.xz

RUN ./Python-3.9.13/configure --with-ensurepip=install

RUN make -j2

RUN make install

RUN rm -fr ./Python-3.9.13/

RUN ldconfig

RUN pip3 install -r requirements.txt

FROM zerotier/zerotier:1.8.10 AS zerotier

COPY --from=dionaea . ./

ENTRYPOINT ["/bin/bash", "-c", "./start.sh"]
