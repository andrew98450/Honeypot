import os
from scapy.all import *

os.system("/usr/local/sbin/entrypoint.sh &")

iface = os.environ["iface"]

sniff(iface=iface, prn=lambda x : x.summary())
