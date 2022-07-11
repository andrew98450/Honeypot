import datetime
import firebase_admin
import configparser
from modules import sniffPacket
from scapy.all import *
from scapy.layers.inet import *
from firebase_admin import credentials
from firebase_admin import db

config = configparser.ConfigParser()
config.read("setting.conf")

iface = str(config.get("env", "iface"))
cred_file = "honeypot.json"
cred = credentials.Certificate()
firebase_admin.initialize_app(cred, {'databaseURL' : 'https://honeypot-349512-default-rtdb.firebaseio.com/'})
ref = db.reference(path='/')
log_ref = ref.child("timestamp")

def onSniff(packet : Packet):
    time_ref = log_ref.child(str(int(datetime.timestamp(datetime.now()))))
    sniffPacket(packet, time_ref)

sniff(iface=iface, prn=onSniff)
