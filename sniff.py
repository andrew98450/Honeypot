
import firebase_admin
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
cred = credentials.Certificate(cred_file)
firebase_admin.initialize_app(cred, {'databaseURL' : 'https://honeypot-349512-default-rtdb.firebaseio.com/'})
ref = db.reference(path='/')
connect_ref = ref.child("connect_info")
blacklist_ref = ref.child("blacklist")
event_ref = ref.child("event")

def onSniff(packet : Packet):
    get_information(packet, ref)
    filter_blacklist(packet, blacklist_ref, iface)
    arp_spoof_detect(packet, event_ref, iface)
    syn_flood_detect(packet, event_ref)
    port_tcp_scan_detect(packet, event_ref)
    port_xmas_scan_detect(packet, event_ref)
    port_null_scan_detect(packet, event_ref)
    port_fin_scan_detect(packet, event_ref)
    shellcode_detect(packet, event_ref)

sniff(iface=iface, prn=onSniff)