IFACE=ztkse4hw57
NATIP=172.17.0.2

sudo sysctl -p /opt/honeypot/sysctl.conf
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 21 -j DNAT --to-destination $NATIP:21
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 22 -j DNAT --to-destination $NATIP:22
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 23 -j DNAT --to-destination $NATIP:23
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 25 -j DNAT --to-destination $NATIP:25
sudo iptables -t nat -A PREROUTING -i $IFACE -p udp --dport 53 -j DNAT --to-destination $NATIP:53
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 80 -j DNAT --to-destination $NATIP:80
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 111 -j DNAT --to-destination $NATIP:111
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 139 -j DNAT --to-destination $NATIP:139
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 445 -j DNAT --to-destination $NATIP:445
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 512 -j DNAT --to-destination $NATIP:512
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 513 -j DNAT --to-destination $NATIP:513
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 514 -j DNAT --to-destination $NATIP:514
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 2049 -j DNAT --to-destination $NATIP:2049
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 2121 -j DNAT --to-destination $NATIP:2121
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 3306 -j DNAT --to-destination $NATIP:3306
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 5432 -j DNAT --to-destination $NATIP:5432
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 5900 -j DNAT --to-destination $NATIP:5900
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 6000 -j DNAT --to-destination $NATIP:6000
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 21 --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 22 --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 22 --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 23 --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 25 --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p udp --dport 53 --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 80 --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 111 --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 139 --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 445 --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 512 --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 513 --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 514 --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 2049 --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 2121 --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 3306 --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 5432 --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 5900 --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 6000 --dst $NATIP -j MASQUERADE
sudo iptables -A FORWARD -p tcp --dport 21 -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 22 -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 23 -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 25 -j ACCEPT
sudo iptables -A FORWARD -p udp --dport 53 -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 80 -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 111 -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 139 -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 445 -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 512 -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 513 -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 514 -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 2049 -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 2121 -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 3306 -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 5432 -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 5900 -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 6000 -j ACCEPT
sudo iptables-save > /opt/honeypot/iptables.conf
sudo python3 /opt/honeypot/sniff.py