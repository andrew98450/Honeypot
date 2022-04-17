from scapy.all import *
import logging

def printlog(packet):
    logging.basicConfig(filename="log.txt", filemode="w")
    logging.info(packet)

sniff(iface="eth0", prn = printlog)