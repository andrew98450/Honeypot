import datetime
import firebase_admin
import configparser
from modules import *
from scapy.all import *
from scapy.layers.inet import *
from firebase_admin import credentials
from firebase_admin import db

config = configparser.ConfigParser()
config.read("setting.conf")

iface = str(config.get("env", "iface"))
cred_file = str(config.get("env", "cred"))
cred = credentials.Certificate(cred_file)
firebase_admin.initialize_app(cred, {'databaseURL' : 'https://honeypot-349512-default-rtdb.firebaseio.com/'})
ref = db.reference(path='/')
log_ref = ref.child("timestamp")
blacklist_ref = ref.child("blacklist")

def onSniff(packet : Packet):
    '''
    time_ref = log_ref.child(str(int(datetime.timestamp(datetime.now()))))
    sniffPacket(packet, time_ref)
    '''
    get_information(packet)


sniff(iface=iface, prn=onSniff)
