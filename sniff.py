import os
from scapy.all import *

iface = os.environ["iface"]

sniff(iface=iface, prn=lambda x : x.summary())