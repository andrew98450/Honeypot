sudo mkdir /opt/honeypot/
sudo cp -fr ./ /opt/honeypot/
sudo cp honeypot.service /etc/systemd/system/
sudo systemctl start honeypot
sudo systemctl enable honeypot