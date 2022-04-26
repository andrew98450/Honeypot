FROM dinotools/dionaea:nightly AS dionaea

COPY . ./

RUN apt-get install -y python3-pip

RUN pip3 install -r requirements.txt

FROM zerotier/zerotier:latest AS zerotier

COPY --from=dionaea . ./

