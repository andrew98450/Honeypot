apt install python3 python3-pip autoconf git unzip net-tools nano gcc wget tar iptables curl libtool
unzip libemu-1.0.4.zip
cd libemu-1.0.4
autoreconf -v -i
./configure
make
make install
cd ..
pip3 install -r requirements.txt
chmod +x start.sh
wget https://lcamtuf.coredump.cx/p0f3/releases/old/2.x/p0f-2.0.8.tgz
tar xvf p0f-2.0.8.tgz
mkdir /opt/local
mv p0f/p0f.fp /opt/local
mv p0f/p0fa.fp /opt/local
mv p0f/p0fr.fp /opt/local
mv p0f/p0fo.fp /opt/local
rm -fr p0f/
rm p0f-2.0.8.tgz
mkdir /opt/honeypot/
cp -fr * /opt/honeypot/
cp honeypot.service /etc/systemd/system/
