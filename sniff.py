import os
import subprocess
from scapy.all import *
from module import *

iface = os.environ["iface"]

def onSniff(packet : Packet):
    pass

sniff(iface=iface, prn=onSniff)
