import firebase_admin
import os
import configparser
from scapy.all import *
from scapy.layers.inet import *
from firebase_admin import credentials
from firebase_admin import db
from modules import *

config = configparser.ConfigParser()
config.read("setting.conf")
iface = str(config.get("env", "iface"))
cred_file = str(config.get("env", "cred"))
nat_ip = str(config.get("env", "natip"))
cred = credentials.Certificate(cred_file)
firebase_admin.initialize_app(cred, {'databaseURL' : 'https://honeypot-349512-default-rtdb.firebaseio.com/'})
ref = db.reference(path='/')
connect_ref = ref.child("connect_info")
blacklist_ref = ref.child("blacklist")
event_ref = ref.child("event")

def init():
    os.system("iptables -t nat -F")
    os.system("iptables -t nat -A PREROUTING -i %s -p tcp -s any/0 --dport 21 -j DNAT --to-destination %s:21" % (iface, nat_ip))
    os.system("iptables -t nat -A PREROUTING -i %s -p tcp -s any/0 --dport 22 -j DNAT --to-destination %s:22" % (iface, nat_ip))
    os.system("iptables -t nat -A PREROUTING -i %s -p tcp -s any/0 --dport 23 -j DNAT --to-destination %s:23" % (iface, nat_ip))
    os.system("iptables -t nat -A PREROUTING -i %s -p tcp -s any/0 --dport 25 -j DNAT --to-destination %s:25" % (iface, nat_ip))
    os.system("iptables -t nat -A PREROUTING -i %s -p udp -s any/0 --dport 53 -j DNAT --to-destination %s:53" % (iface, nat_ip))
    os.system("iptables -t nat -A PREROUTING -i %s -p tcp -s any/0 --dport 80 -j DNAT --to-destination %s:80" % (iface, nat_ip))
    os.system("iptables -t nat -A PREROUTING -i %s -p tcp -s any/0 --dport 111 -j DNAT --to-destination %s:111" % (iface, nat_ip))
    os.system("iptables -t nat -A PREROUTING -i %s -p tcp -s any/0 --dport 139 -j DNAT --to-destination %s:139" % (iface, nat_ip))
    os.system("iptables -t nat -A PREROUTING -i %s -p tcp -s any/0 --dport 445 -j DNAT --to-destination %s:445" % (iface, nat_ip))
    os.system("iptables -t nat -A PREROUTING -i %s -p tcp -s any/0 --dport 512 -j DNAT --to-destination %s:512" % (iface, nat_ip))
    os.system("iptables -t nat -A PREROUTING -i %s -p tcp -s any/0 --dport 513 -j DNAT --to-destination %s:513" % (iface, nat_ip))
    os.system("iptables -t nat -A PREROUTING -i %s -p tcp -s any/0 --dport 514 -j DNAT --to-destination %s:514" % (iface, nat_ip))
    os.system("iptables -t nat -A PREROUTING -i %s -p tcp -s any/0 --dport 2049 -j DNAT --to-destination %s:2049" % (iface, nat_ip))
    os.system("iptables -t nat -A PREROUTING -i %s -p tcp -s any/0 --dport 2121 -j DNAT --to-destination %s:2121" % (iface, nat_ip))
    os.system("iptables -t nat -A PREROUTING -i %s -p tcp -s any/0 --dport 3306 -j DNAT --to-destination %s:3306" % (iface, nat_ip))
    os.system("iptables -t nat -A PREROUTING -i %s -p tcp -s any/0 --dport 5432 -j DNAT --to-destination %s:5432" % (iface, nat_ip))
    os.system("iptables -t nat -A PREROUTING -i %s -p tcp -s any/0 --dport 5900 -j DNAT --to-destination %s:5900" % (iface, nat_ip))
    os.system("iptables -t nat -A PREROUTING -i %s -p tcp -s any/0 --dport 6000 -j DNAT --to-destination %s:6000" % (iface, nat_ip))
    os.system("iptables -t nat -A POSTROUTING -o %s -p tcp --dport 21 --dst %s -j MASQUERADE" % (iface, nat_ip))
    os.system("iptables -t nat -A POSTROUTING -o %s -p tcp --dport 22 --dst %s -j MASQUERADE" % (iface, nat_ip))
    os.system("iptables -t nat -A POSTROUTING -o %s -p tcp --dport 22 --dst %s -j MASQUERADE" % (iface, nat_ip))
    os.system("iptables -t nat -A POSTROUTING -o %s -p tcp --dport 23 --dst %s -j MASQUERADE" % (iface, nat_ip))
    os.system("iptables -t nat -A POSTROUTING -o %s -p tcp --dport 25 --dst %s -j MASQUERADE" % (iface, nat_ip))
    os.system("iptables -t nat -A POSTROUTING -o %s -p udp --dport 53 --dst %s -j MASQUERADE" % (iface, nat_ip))
    os.system("iptables -t nat -A POSTROUTING -o %s -p tcp --dport 80 --dst %s -j MASQUERADE" % (iface, nat_ip))
    os.system("iptables -t nat -A POSTROUTING -o %s -p tcp --dport 111 --dst %s -j MASQUERADE" % (iface, nat_ip))
    os.system("iptables -t nat -A POSTROUTING -o %s -p tcp --dport 139 --dst %s -j MASQUERADE" % (iface, nat_ip))
    os.system("iptables -t nat -A POSTROUTING -o %s -p tcp --dport 445 --dst %s -j MASQUERADE" % (iface, nat_ip))
    os.system("iptables -t nat -A POSTROUTING -o %s -p tcp --dport 512 --dst %s -j MASQUERADE" % (iface, nat_ip))
    os.system("iptables -t nat -A POSTROUTING -o %s -p tcp --dport 513 --dst %s -j MASQUERADE" % (iface, nat_ip))
    os.system("iptables -t nat -A POSTROUTING -o %s -p tcp --dport 514 --dst %s -j MASQUERADE" % (iface, nat_ip))
    os.system("iptables -t nat -A POSTROUTING -o %s -p tcp --dport 2049 --dst %s -j MASQUERADE" % (iface, nat_ip))
    os.system("iptables -t nat -A POSTROUTING -o %s -p tcp --dport 2121 --dst %s -j MASQUERADE" % (iface, nat_ip))
    os.system("iptables -t nat -A POSTROUTING -o %s -p tcp --dport 3306 --dst %s -j MASQUERADE" % (iface, nat_ip))
    os.system("iptables -t nat -A POSTROUTING -o %s -p tcp --dport 5432 --dst %s -j MASQUERADE" % (iface, nat_ip))
    os.system("iptables -t nat -A POSTROUTING -o %s -p tcp --dport 5900 --dst %s -j MASQUERADE" % (iface, nat_ip))
    os.system("iptables -t nat -A POSTROUTING -o %s -p tcp --dport 6000 --dst %s -j MASQUERADE" % (iface, nat_ip))
    
def onSniff(packet : Packet):
    get_information(packet, ref)
    filter_blacklist(packet, blacklist_ref, iface)
    #arp_spoof_detect(packet, event_ref, iface)
    syn_flood_detect(packet, event_ref)
    #port_tcp_scan_detect(packet, event_ref)
    port_xmas_scan_detect(packet, event_ref)
    port_null_scan_detect(packet, event_ref)
    port_fin_scan_detect(packet, event_ref)
    shellcode_detect(packet, event_ref)

init()
sniff(iface=iface, prn=onSniff)