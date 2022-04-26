FROM dinotools/dionaea:nightly AS dionaea

COPY . ./

RUN pip3 install -r requirements.txt

FROM zerotier/zerotier:latest AS zerotier

COPY --from=dionaea . ./

