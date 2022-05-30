from scapy.all import *
from scapy.layers.inet import *
from firebase_admin import db

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