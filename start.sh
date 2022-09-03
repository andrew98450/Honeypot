IFACE=ztkse4hw57
NATIP=172.17.0.2

sudo sysctl -p sysctl.conf
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 21 --tcp-flags ALL ALL -j DNAT --to-destination $NATIP:21
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 22 --tcp-flags ALL ALL -j DNAT --to-destination $NATIP:22
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 23 --tcp-flags ALL ALL -j DNAT --to-destination $NATIP:23
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 25 --tcp-flags ALL ALL -j DNAT --to-destination $NATIP:25
sudo iptables -t nat -A PREROUTING -i $IFACE -p udp --dport 53 -j DNAT --to-destination $NATIP:53
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 80 --tcp-flags ALL ALL -j DNAT --to-destination $NATIP:80
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 111 --tcp-flags ALL ALL -j DNAT --to-destination $NATIP:111
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 139 --tcp-flags ALL ALL -j DNAT --to-destination $NATIP:139
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 445 --tcp-flags ALL ALL -j DNAT --to-destination $NATIP:445
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 512 --tcp-flags ALL ALL -j DNAT --to-destination $NATIP:512
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 513 --tcp-flags ALL ALL -j DNAT --to-destination $NATIP:513
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 514 --tcp-flags ALL ALL -j DNAT --to-destination $NATIP:514
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 2049 --tcp-flags ALL ALL -j DNAT --to-destination $NATIP:2049
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 2121 --tcp-flags ALL ALL -j DNAT --to-destination $NATIP:2121
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 3306 --tcp-flags ALL ALL -j DNAT --to-destination $NATIP:3306
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 5432 --tcp-flags ALL ALL -j DNAT --to-destination $NATIP:5432
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 5900 --tcp-flags ALL ALL -j DNAT --to-destination $NATIP:5900
sudo iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 6000 --tcp-flags ALL ALL -j DNAT --to-destination $NATIP:6000
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 21 --tcp-flags ALL ALL --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 22 --tcp-flags ALL ALL --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 22 --tcp-flags ALL ALL --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 23 --tcp-flags ALL ALL --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 25 --tcp-flags ALL ALL --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p udp --dport 53 --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 80 --tcp-flags ALL ALL --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 111 --tcp-flags ALL ALL --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 139 --tcp-flags ALL ALL --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 445 --tcp-flags ALL ALL --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 512 --tcp-flags ALL ALL --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 513 --tcp-flags ALL ALL --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 514 --tcp-flags ALL ALL --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 2049 --tcp-flags ALL ALL --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 2121 --tcp-flags ALL ALL --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 3306 --tcp-flags ALL ALL --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 5432 --tcp-flags ALL ALL --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 5900 --tcp-flags ALL ALL --dst $NATIP -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -o $IFACE -p tcp --dport 6000 --tcp-flags ALL ALL --dst $NATIP -j MASQUERADE
sudo iptables -A FORWARD -p tcp --dport 21 --tcp-flags ALL ALL -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 22 --tcp-flags ALL ALL -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 23 --tcp-flags ALL ALL -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 25 --tcp-flags ALL ALL -j ACCEPT
sudo iptables -A FORWARD -p udp --dport 53 -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 80 --tcp-flags ALL ALL -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 111 --tcp-flags ALL ALL -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 139 --tcp-flags ALL ALL -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 445 --tcp-flags ALL ALL -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 512 --tcp-flags ALL ALL -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 513 --tcp-flags ALL ALL -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 514 --tcp-flags ALL ALL -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 2049 --tcp-flags ALL ALL -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 2121 --tcp-flags ALL ALL -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 3306 --tcp-flags ALL ALL -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 5432 --tcp-flags ALL ALL -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 5900 --tcp-flags ALL ALL -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 6000 --tcp-flags ALL ALL -j ACCEPT

sudo python3 sniff.py