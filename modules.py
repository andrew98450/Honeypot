import pyemu
from scapy.all import *
from scapy.layers.all import Raw
from scapy.layers.inet import *
from scapy.layers.l2 import *
from scapy.modules.p0f import *
from firebase_admin import db
from protocol import Protocol

ports = {21 : Protocol.FTP, 23 : Protocol.TELNET, 53 : Protocol.DNS, 
    80 : Protocol.HTTP, 443 : Protocol.HTTPS, 445 : Protocol.SMB}
 
def filter_blacklist(packet : Packet, blacklist_ref : db.Reference):
    get_blacklist_ref = blacklist_ref.get()
    if packet.haslayer(IP):
        if packet.haslayer(TCP):
            ip_field = packet.getlayer(IP)
            tcp_field = packet.getlayer(TCP)
            src_ip = ip_field.src
            target_port = tcp_field.dport

def shellcode_detect(packet : Packet):
    if packet.haslayer(Raw):
        raw_field = packet.getlayer(Raw)
        
def arp_detect(packet : Packet):
    if packet.haslayer(ARP):
        arp_field = packet.getlayer(ARP)

def sniffPacket(packet : Packet, time_ref : db.Reference):
    if packet.haslayer(IP):
        if packet.haslayer(TCP):
            ip_field = packet.getlayer(IP)
            tcp_field = packet.getlayer(TCP)
            time_ref.set({
                'protocol' : 'TCP',
                'ttl' : ip_field.ttl,
                'tos' : ip_field.tos,
                'src_address' : ip_field.src,
                'dst_address' : ip_field.dst,
                'src_port' : tcp_field.sport,
                'dst_port' : tcp_field.dport,
            })
        elif packet.haslayer(UDP):
            ip_field = packet.getlayer(IP)
            udp_field = packet.getlayer(UDP)
            time_ref.set({
                'protocol' : 'UDP',
                'ttl' : ip_field.ttl,
                'tos' : ip_field.tos,
                'src_address' : ip_field.src,
                'dst_address' : ip_field.dst,
                'src_port' : udp_field.sport,
                'dst_port' : udp_field.dport,
            })