sudo apt install python3 python3-pip autoconf git net-tools nano gcc wget tar iptables curl libtool
git clone https://github.com/buffer/libemu.git
cd libemu
autoreconf -v -i
./configure
make
sudo make install
cd ..
sudo pip3 install -r requirements.txt
chmod +x start.sh
wget https://lcamtuf.coredump.cx/p0f3/releases/old/2.x/p0f-2.0.8.tgz
tar xvf p0f-2.0.8.tgz
sudo mkdir /opt/local
sudo mv p0f/p0f.fp /opt/local
sudo mv p0f/p0fa.fp /opt/local
sudo mv p0f/p0fr.fp /opt/local
sudo mv p0f/p0fo.fp /opt/local
rm -fr p0f/
rm p0f-2.0.8.tgz
sudo mkdir /opt/honeypot/
sudo cp -fr * /opt/honeypot/
sudo cp honeypot.service /etc/systemd/system/
