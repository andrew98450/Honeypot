import pickle
import time
from pyptables import *
from scapy.all import *
from scapy.layers.all import *
from scapy.layers.http import *
from scapy.layers.dns import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
from scapy.layers.tftp import *
from scapy.modules.p0f import *
from firebase_admin import db
from protocol import Protocol
from pylibemu import Emulator

ports = {21 : Protocol.FTP, 23 : Protocol.TELNET, 53 : Protocol.DNS, 
    80 : Protocol.HTTP, 443 : Protocol.HTTPS, 445 : Protocol.SMB,
    1433: Protocol.MSSQL, 3306: Protocol.MYSQL}
emu = Emulator()
tables = default_tables()
syn_table = dict()

if not os.path.exists('blacktable.filter'):
    filted_table = dict()
else:
    filted_table = pickle.load(open('blacktable.filter', 'rb'))

def filter_blacklist(packet : Packet, blacklist_ref : db.Reference, iface : str):
    blacklist = blacklist_ref.get()
    if blacklist is None:
        return
    inputs = tables['filter']['INPUT']
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_field = packet[IP]
        tcp_field = packet[TCP]
        src_ip = str(ip_field.src)
        target_port = tcp_field.dport
        if src_ip.replace('.', '-') in blacklist.keys() and tcp_field.flags == 0x02:
            drop_rule = Drop(i=iface, s=src_ip, dport=str(target_port), proto='tcp')
            if src_ip not in filted_table.keys():
                filted_table[src_ip] = {target_port: drop_rule}
            if src_ip in filted_table.keys() and target_port not in filted_table[src_ip].keys():
                filted_table[src_ip][target_port] = drop_rule
            inputs.append(drop_rule)
        if src_ip.replace('.', '-') not in blacklist.keys() and tcp_field.flags == 0x02:
            if src_ip in filted_table.keys():
                inputs.remove(filted_table[src_ip][target_port])
                filted_table.pop(src_ip)
        restore(tables)
        pickle.dump(filted_table, open('blacktable.filter', 'wb'))
    elif packet.haslayer(IP) and packet.haslayer(UDP):
        ip_field = packet[IP]
        udp_field = packet[UDP]
        src_ip = str(ip_field.src)
        target_port = udp_field.dport
        if src_ip.replace('.', '-') in blacklist.keys():
            drop_rule = Drop(i=iface, s=src_ip, dport=str(target_port), proto='udp')
            if src_ip not in filted_table.keys():
                filted_table[src_ip] = {target_port: drop_rule}
            if src_ip in filted_table.keys() and target_port not in filted_table[src_ip].keys():
                filted_table[src_ip][target_port] = drop_rule
            inputs.append(drop_rule)
        if src_ip.replace('.', '-') not in blacklist.keys():
            if src_ip in filted_table.keys():
                inputs.remove(filted_table[src_ip][target_port])
                filted_table.pop(src_ip)
        restore(tables)
        pickle.dump(filted_table, open('blacktable.filter', 'wb'))

def get_information(packet : Packet, ref : db.Reference):
    info_ref = ref.child('info')
   
    if packet.haslayer(IP):
        if packet.haslayer(TCP):
            ip_field = packet[IP]
            src_ip = ip_field.src
            info = p0f(packet)
            ip_ref = info_ref.child(str(src_ip).replace('.', '-'))
            ip_ref.update({
                'sysinfo' : info
            })
            
def shellcode_detect(packet : Packet, event_ref : db.Reference):

    if packet.haslayer(IP):
        if packet.haslayer(TCP):

            ip_field = packet[IP]
            tcp_field = packet[TCP]
            if packet.haslayer(Raw) and len(packet[Raw].original) > 0:
                raw_field = packet[Raw]
                payload = raw_field.original
                src_ip = ip_field.src
                target_port = tcp_field.dport
                if target_port not in ports.keys():
                    protocol = 'other'
                elif ports[target_port] == Protocol.FTP:
                    protocol = 'ftp'
                elif ports[target_port] == Protocol.TELNET:
                    protocol = 'telnet'
                elif ports[target_port] == Protocol.DNS:
                    protocol = 'dns'
                elif ports[target_port] == Protocol.HTTP:
                    protocol = 'http'
                elif ports[target_port] == Protocol.HTTPS:
                    protocol = 'https'
                elif ports[target_port] == Protocol.SMB:
                    protocol = 'smb'
                elif ports[target_port] == Protocol.MSSQL:
                    protocol = 'mssql'
                elif ports[target_port] == Protocol.MYSQL:
                    protocol = 'mysql'

                offset = emu.shellcode_getpc_test(payload)
                if offset is not None and offset >= 0:
                    time_ref = event_ref.child(
                        str(int(time.time())))
                    time_ref.update({
                        "event_type" : "ShellCode",
                        "protocol" : protocol,
                        "src_ip" : src_ip
                    })
            
def syn_flood_detect(packet : Packet, event_ref : db.Reference):
    
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_field = packet.getlayer(IP)
        tcp_field = packet.getlayer(TCP)
        src_ip = ip_field.src
        if tcp_field.flags & 2 and tcp_field.dport == 80:
            syn_table[src_ip] += 1
            if syn_table[src_ip] > 30 and tcp_field.ack == 0:
                time_ref = event_ref.child(
                    str(int(time.time())))
                time_ref.update({
                    "event_type" : "Syn Flood",
                    "protocol" : 'TCP',
                    "src_ip" : src_ip
                })

'''
def arp_spoof_detect(packet : Packet, event_ref : db.Reference, iface : str):
    
    def get_mac(ip_address, iface):
        arp_request = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip_address)
        result = srp1(arp_request, iface=iface, timeout=1, verbose=False)
        if result.haslayer(Ether):
            eth_data = result.getlayer(Ether)
            return eth_data.hwsrc

    if packet.haslayer(ARP):
        arp_field = packet.getlayer(ARP)
        if arp_field.op == 2:
            real_mac_address = get_mac(arp_field.psrc, iface)
            response_mac_address = arp_field.hwsrc
            if real_mac_address != response_mac_address:
                time_ref = event_ref.child(
                    str(int(time.time())))
                time_ref.update({
                    "event_type" : "ARP Spoofing",
                    "protocol" : 'ARP',
                    "src_ip" : arp_field.psrc
                })
'''

def dns_fuzz_detect(packet : Packet, event_ref : db.Reference, iface : str):
    if packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS):
        ip_field = packet[IP]
        udp_field = packet[UDP]
        dns_field = packet[DNS]
        if udp_field.dport == 53 and dns_field.qd is not None and dns_field.an is not None:
            time_ref = event_ref.child(
                str(int(time.time())))
            time_ref.update({
                "event_type" : "DNS Fuzz",
                "protocol" : 'DNS',
                "src_ip" : ip_field.src
            })
'''
def port_tcp_scan_detect(packet : Packet, event_ref : db.Reference):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_field = packet.getlayer(IP)
        tcp_field = packet.getlayer(TCP)
        target_port = tcp_field.dport
        if tcp_field.flags == 0x02 and tcp_field.ack == 0:
            if target_port not in ports.keys():
                protocol = 'other'
            elif ports[target_port] == Protocol.FTP:
                protocol = 'ftp'
            elif ports[target_port] == Protocol.TELNET:
                protocol = 'telnet'
            elif ports[target_port] == Protocol.DNS:
                protocol = 'dns'
            elif ports[target_port] == Protocol.HTTP:
                protocol = 'http'
            elif ports[target_port] == Protocol.HTTPS:
                protocol = 'https'
            elif ports[target_port] == Protocol.SMB:
                protocol = 'smb'
            elif ports[target_port] == Protocol.MSSQL:
                protocol = 'mssql'
            elif ports[target_port] == Protocol.MYSQL:
                protocol = 'mysql'
            time_ref = event_ref.child(
                str(int(time.time())))
            time_ref.update({
               "event_type" : "PORT Scan",
                "scan_type" : "TCP",
                "protocol" : protocol,
                "port" : str(target_port),
                "src_ip" : ip_field.src
            })
'''
def port_xmas_scan_detect(packet : Packet, event_ref : db.Reference):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_field = packet.getlayer(IP)
        tcp_field = packet.getlayer(TCP)
        target_port = tcp_field.dport
        if tcp_field.flags == 0x29:
            if target_port not in ports.keys():
                protocol = 'other'
            elif ports[target_port] == Protocol.FTP:
                protocol = 'ftp'
            elif ports[target_port] == Protocol.TELNET:
                protocol = 'telnet'
            elif ports[target_port] == Protocol.DNS:
                protocol = 'dns'
            elif ports[target_port] == Protocol.HTTP:
                protocol = 'http'
            elif ports[target_port] == Protocol.HTTPS:
                protocol = 'https'
            elif ports[target_port] == Protocol.SMB:
                protocol = 'smb'
            elif ports[target_port] == Protocol.MSSQL:
                protocol = 'mssql'
            elif ports[target_port] == Protocol.MYSQL:
                protocol = 'mysql'
            time_ref = event_ref.child(
                str(int(time.time())))
            time_ref.update({
                "event_type" : "PORT Scan",
                "scan_type" : "XMAS",
                "protocol" : protocol,
                "port" : str(target_port),
                "src_ip" : ip_field.src
            })

def port_fin_scan_detect(packet : Packet, event_ref : db.Reference):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_field = packet.getlayer(IP)
        tcp_field = packet.getlayer(TCP)
        target_port = tcp_field.dport
        if tcp_field.flags == 0x01:
            if target_port not in ports.keys():
                protocol = 'other'
            elif ports[target_port] == Protocol.FTP:
                protocol = 'ftp'
            elif ports[target_port] == Protocol.TELNET:
                protocol = 'telnet'
            elif ports[target_port] == Protocol.DNS:
                protocol = 'dns'
            elif ports[target_port] == Protocol.HTTP:
                protocol = 'http'
            elif ports[target_port] == Protocol.HTTPS:
                protocol = 'https'
            elif ports[target_port] == Protocol.SMB:
                protocol = 'smb'
            elif ports[target_port] == Protocol.MSSQL:
                protocol = 'mssql'
            elif ports[target_port] == Protocol.MYSQL:
                protocol = 'mysql'
            time_ref = event_ref.child(
                str(int(time.time())))
            time_ref.update({
                "event_type" : "PORT Scan",
                "scan_type" : "FIN",
                "protocol" : protocol,
                "port" : str(target_port),
                "src_ip" : ip_field.src
            })
            
def port_null_scan_detect(packet : Packet, event_ref : db.Reference):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_field = packet.getlayer(IP)
        tcp_field = packet.getlayer(TCP)
        target_port = tcp_field.dport
        if tcp_field.flags == 0x00:
            if target_port not in ports.keys():
                protocol = 'other'
            elif ports[target_port] == Protocol.FTP:
                protocol = 'ftp'
            elif ports[target_port] == Protocol.TELNET:
                protocol = 'telnet'
            elif ports[target_port] == Protocol.DNS:
                protocol = 'dns'
            elif ports[target_port] == Protocol.HTTP:
                protocol = 'http'
            elif ports[target_port] == Protocol.HTTPS:
                protocol = 'https'
            elif ports[target_port] == Protocol.SMB:
                protocol = 'smb'
            elif ports[target_port] == Protocol.MSSQL:
                protocol = 'mssql'
            elif ports[target_port] == Protocol.MYSQL:
                protocol = 'mysql'
            time_ref = event_ref.child(
                str(int(time.time())))
            time_ref.update({
                "event_type" : "PORT Scan",
                "scan_type" : "NULL",
                "protocol" : protocol,
                "port" : str(target_port),
                "src_ip" : ip_field.src
            })

def port_ack_scan_detect(packet : Packet, event_ref : db.Reference):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_field = packet.getlayer(IP)
        tcp_field = packet.getlayer(TCP)
        target_port = tcp_field.dport
        if tcp_field.flags == 0x10:
            if target_port not in ports.keys():
                protocol = 'other'
            elif ports[target_port] == Protocol.FTP:
                protocol = 'ftp'
            elif ports[target_port] == Protocol.TELNET:
                protocol = 'telnet'
            elif ports[target_port] == Protocol.DNS:
                protocol = 'dns'
            elif ports[target_port] == Protocol.HTTP:
                protocol = 'http'
            elif ports[target_port] == Protocol.HTTPS:
                protocol = 'https'
            elif ports[target_port] == Protocol.SMB:
                protocol = 'smb'
            elif ports[target_port] == Protocol.MSSQL:
                protocol = 'mssql'
            elif ports[target_port] == Protocol.MYSQL:
                protocol = 'mysql'
            time_ref = event_ref.child(
                str(int(time.time())))
            time_ref.update({
                "event_type" : "PORT Scan",
                "scan_type" : "ACK",
                "protocol" : protocol,
                "port" : str(target_port),
                "src_ip" : ip_field.src
            })

def sniffPacket(packet : Packet, time_ref : db.Reference):
    if packet.haslayer(IP):
        if packet.haslayer(TCP):
            ip_field = packet.getlayer(IP)
            tcp_field = packet.getlayer(TCP)
            target_port = tcp_field.dport
            if target_port not in ports.keys():
                protocol = 'other'
            elif ports[target_port] == Protocol.FTP:
                protocol = 'ftp'
            elif ports[target_port] == Protocol.TELNET:
                protocol = 'telnet'
            elif ports[target_port] == Protocol.DNS:
                protocol = 'dns'
            elif ports[target_port] == Protocol.HTTP:
                protocol = 'http'
            elif ports[target_port] == Protocol.HTTPS:
                protocol = 'https'
            elif ports[target_port] == Protocol.SMB:
                protocol = 'smb'
            elif ports[target_port] == Protocol.MSSQL:
                protocol = 'mssql'
            elif ports[target_port] == Protocol.MYSQL:
                protocol = 'mysql'
            time_ref.update({
                'protocol' : protocol,
                'ttl' : ip_field.ttl,
                'tos' : ip_field.tos,
                'src_address' : ip_field.src,
                'dst_address' : ip_field.dst,
                'src_port' : tcp_field.sport,
                'dst_port' : tcp_field.dport,
            })
        elif packet.haslayer(UDP):
            ip_field = packet.getlayer(IP)
            tcp_field = packet.getlayer(UDP)
            target_port = tcp_field.dport
            if target_port not in ports.keys():
                protocol = 'other'
            elif ports[target_port] == Protocol.FTP:
                protocol = 'ftp'
            elif ports[target_port] == Protocol.TELNET:
                protocol = 'telnet'
            elif ports[target_port] == Protocol.DNS:
                protocol = 'dns'
            elif ports[target_port] == Protocol.HTTP:
                protocol = 'http'
            elif ports[target_port] == Protocol.HTTPS:
                protocol = 'https'
            elif ports[target_port] == Protocol.SMB:
                protocol = 'smb'
            elif ports[target_port] == Protocol.MSSQL:
                protocol = 'mssql'
            elif ports[target_port] == Protocol.MYSQL:
                protocol = 'mysql'
            time_ref.update({
                'protocol' : protocol,
                'ttl' : ip_field.ttl,
                'tos' : ip_field.tos,
                'src_address' : ip_field.src,
                'dst_address' : ip_field.dst,
                'src_port' : tcp_field.sport,
                'dst_port' : tcp_field.dport,
            })