import os
import datetime
import firebase_admin
from modules import sniffPacket
from scapy.all import *
from scapy.layers.inet import *
from firebase_admin import credentials
from firebase_admin import db

iface = conf.iface
cred = credentials.Certificate('./honeypot-349512-firebase-adminsdk-ltg68-eefb2c5bf1.json')
firebase_admin.initialize_app(cred, {'databaseURL' : 'https://honeypot-349512-default-rtdb.firebaseio.com/'})
ref = db.reference(path='/')
log_ref = ref.child("timestamp")

def onSniff(packet : Packet):
    time_ref = log_ref.child(str(int(datetime.timestamp(datetime.now()))))
    sniffPacket(packet, time_ref)

sniff(iface=iface, prn=onSniff)
