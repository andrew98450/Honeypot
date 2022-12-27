import os
import time
from scapy.all import *
from scapy.layers.all import *
from scapy.layers.http import *
from scapy.layers.dns import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
from scapy.modules.p0f import *
from firebase_admin import db
from protocol import Protocol
from pylibemu import Emulator

ports = {21 : Protocol.FTP, 22: Protocol.SSH, 23 : Protocol.TELNET,
    25: Protocol.SMTP, 53 : Protocol.DNS, 80 : Protocol.HTTP, 
    111: Protocol.RPCBIND, 139: Protocol.NETBIOS, 445 : Protocol.SMB,
    512: Protocol.EXEC, 513: Protocol.LOGIN, 514: Protocol.SHELL,
    2121: Protocol.CCPROXY, 3306: Protocol.MYSQL, 5432: Protocol.POSTGRESQL, 5900: Protocol.VNC,
    6000: Protocol.X11}
emu = Emulator()
syn_table = dict()
filted_table = []

def filter_blacklist(packet : Packet, blacklist_ref : db.Reference, iface : str):
    blacklist = blacklist_ref.get()
    
    if blacklist is None:
        blacklist = dict()
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_field = packet[IP]
        tcp_field = packet[TCP]
        src_ip = str(ip_field.src)
        for blacklist_ip in blacklist:
            if blacklist_ip.replace('-', '.') not in filted_table:
                os.system("sudo iptables -A FORWARD -i %s -p tcp --tcp-flags SYN SYN -s %s -j DROP"
                    % (iface, blacklist_ip.replace('-', '.')))
                filted_table.append(blacklist_ip.replace('-', '.'))
            else:
                os.system("sudo iptables -R FORWARD %d -i %s -p tcp --tcp-flags SYN SYN -s %s -j DROP"
                    % (filted_table.index(blacklist_ip.replace('-', '.')) + 1, iface, blacklist_ip.replace('-', '.')))
        if src_ip.replace('.', '-') not in blacklist.keys() and tcp_field.flags == 0x02:
            if src_ip in filted_table:
                os.system("sudo iptables -R FORWARD %d -i %s -p tcp --tcp-flags SYN SYN -s %s -j ACCEPT"
                    % (filted_table.index(src_ip) + 1, iface, src_ip))
                filted_table.remove(src_ip)

def get_information(packet : Packet, ref : db.Reference):
    info_ref = ref.child('info')
   
    if packet.haslayer(IP):
        if packet.haslayer(TCP):
            ip_field = packet[IP]
            src_ip = ip_field.dst
            info = p0f(packet)
            ip_ref = info_ref.child(str(src_ip).replace('.', '-'))
            ip_ref.update({
                'sysinfo' : info
            })
            
def shellcode_detect(packet : Packet, event_ref : db.Reference):
    protocol = ''
    if packet.haslayer(IP):
        if packet.haslayer(TCP):

            ip_field = packet[IP]
            tcp_field = packet[TCP]
            if packet.haslayer(Raw):
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
                elif ports[target_port] == Protocol.SMTP:
                    protocol = 'smtp'
                elif ports[target_port] == Protocol.DNS:
                    protocol = 'dns'
                elif ports[target_port] == Protocol.HTTP:
                    protocol = 'http'
                elif ports[target_port] == Protocol.RPCBIND:
                    protocol = 'rpcbind'
                elif ports[target_port] == Protocol.NETBIOS:
                    protocol = 'netbios'
                elif ports[target_port] == Protocol.SMB:
                    protocol = 'smb'
                elif ports[target_port] == Protocol.EXEC:
                    protocol = 'exec'
                elif ports[target_port] == Protocol.LOGIN:
                    protocol = 'login'
                elif ports[target_port] == Protocol.SHELL:
                    protocol = 'shell'
                elif ports[target_port] == Protocol.CCPROXY:
                    protocol = 'ccproxy'
                elif ports[target_port] == Protocol.MYSQL:
                    protocol = 'mysql'
                elif ports[target_port] == Protocol.POSTGRESQL:
                    protocol = 'postgresql'
                elif ports[target_port] == Protocol.VNC:
                    protocol = 'vnc'
                elif ports[target_port] == Protocol.X11:
                    protocol = 'x11'

                offset = emu.shellcode_getpc_test(payload)
                if offset is not None and offset >= 0:
                    time_ref = event_ref.child(
                        str(int(time.time())))
                    time_ref.update({
                        "event_type" : "ShellCode",
                        "protocol" : protocol,
                        "port": target_port,
                        "src_ip" : src_ip
                    })
            
def syn_flood_detect(packet : Packet, event_ref : db.Reference):
    protocol = ''
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_field = packet.getlayer(IP)
        tcp_field = packet.getlayer(TCP)
        src_ip = ip_field.src
        target_port = tcp_field.dport
        if target_port not in ports.keys():
            protocol = 'other'
        elif ports[target_port] == Protocol.FTP:
            protocol = 'ftp'
        elif ports[target_port] == Protocol.TELNET:
            protocol = 'telnet'
        elif ports[target_port] == Protocol.SMTP:
            protocol = 'smtp'
        elif ports[target_port] == Protocol.DNS:
            protocol = 'dns'
        elif ports[target_port] == Protocol.HTTP:
            protocol = 'http'
        elif ports[target_port] == Protocol.RPCBIND:
            protocol = 'rpcbind'
        elif ports[target_port] == Protocol.NETBIOS:
            protocol = 'netbios'
        elif ports[target_port] == Protocol.SMB:
            protocol = 'smb'
        elif ports[target_port] == Protocol.EXEC:
            protocol = 'exec'
        elif ports[target_port] == Protocol.LOGIN:
            protocol = 'login'
        elif ports[target_port] == Protocol.SHELL:
            protocol = 'shell'
        elif ports[target_port] == Protocol.CCPROXY:
            protocol = 'ccproxy'
        elif ports[target_port] == Protocol.MYSQL:
            protocol = 'mysql'
        elif ports[target_port] == Protocol.POSTGRESQL:
            protocol = 'postgresql'
        elif ports[target_port] == Protocol.VNC:
            protocol = 'vnc'
        elif ports[target_port] == Protocol.X11:
            protocol = 'x11'
        if tcp_field.flags & 2:
            if src_ip.replace('.', '-') not in syn_table.keys():
                if tcp_field.ack != 1:
                    syn_table[src_ip.replace('.', '-')] = 1
            else:
                if tcp_field.ack != 1:
                    syn_table[src_ip.replace('.', '-')] += 1
                else:
                    syn_table[src_ip.replace('.', '-')] = 1
                    
            if src_ip.replace('.', '-') in syn_table.keys():
                if syn_table[src_ip.replace('.', '-')] > 200 and tcp_field.ack == 0:
                    time_ref = event_ref.child(
                        str(int(time.time())))
                    time_ref.update({
                        "event_type" : "Syn Flood",
                        "port" : target_port,
                        "protocol" : protocol,
                        "src_ip" : src_ip.replace('.', '-')
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

def dns_fuzz_detect(packet : Packet, event_ref : db.Reference):
    if packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS):
        ip_field = packet[IP]
        udp_field = packet[UDP]
        dns_field = packet[DNS]
        if udp_field.dport == 53 and type(dns_field.qd) is not None and type(dns_field.an) is not None:
            time_ref = event_ref.child(
                str(int(time.time())))
            time_ref.update({
                "event_type" : "DNS Fuzz",
                "protocol" : 'dns',
                "port" : udp_field.dport,
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
    protocol = ''
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
            elif ports[target_port] == Protocol.SMTP:
                protocol = 'smtp'
            elif ports[target_port] == Protocol.DNS:
                protocol = 'dns'
            elif ports[target_port] == Protocol.HTTP:
                protocol = 'http'
            elif ports[target_port] == Protocol.RPCBIND:
                protocol = 'rpcbind'
            elif ports[target_port] == Protocol.NETBIOS:
                protocol = 'netbios'
            elif ports[target_port] == Protocol.SMB:
                protocol = 'smb'
            elif ports[target_port] == Protocol.EXEC:
                protocol = 'exec'
            elif ports[target_port] == Protocol.LOGIN:
                protocol = 'login'
            elif ports[target_port] == Protocol.SHELL:
                protocol = 'shell'
            elif ports[target_port] == Protocol.CCPROXY:
                protocol = 'ccproxy'
            elif ports[target_port] == Protocol.MYSQL:
                protocol = 'mysql'
            elif ports[target_port] == Protocol.POSTGRESQL:
                protocol = 'postgresql'
            elif ports[target_port] == Protocol.VNC:
                protocol = 'vnc'
            elif ports[target_port] == Protocol.X11:
                protocol = 'x11'
            time_ref = event_ref.child(
                str(int(time.time())))
            time_ref.update({
                "event_type" : "PORT Scan",
                "scan_type" : "XMAS",
                "protocol" : protocol,
                "port" : target_port,
                "src_ip" : ip_field.src
            })

def port_fin_scan_detect(packet : Packet, event_ref : db.Reference):
    protocol = ''
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
            elif ports[target_port] == Protocol.SMTP:
                protocol = 'smtp'
            elif ports[target_port] == Protocol.DNS:
                protocol = 'dns'
            elif ports[target_port] == Protocol.HTTP:
                protocol = 'http'
            elif ports[target_port] == Protocol.RPCBIND:
                protocol = 'rpcbind'
            elif ports[target_port] == Protocol.NETBIOS:
                protocol = 'netbios'
            elif ports[target_port] == Protocol.SMB:
                protocol = 'smb'
            elif ports[target_port] == Protocol.EXEC:
                protocol = 'exec'
            elif ports[target_port] == Protocol.LOGIN:
                protocol = 'login'
            elif ports[target_port] == Protocol.SHELL:
                protocol = 'shell'
            elif ports[target_port] == Protocol.CCPROXY:
                protocol = 'ccproxy'
            elif ports[target_port] == Protocol.MYSQL:
                protocol = 'mysql'
            elif ports[target_port] == Protocol.POSTGRESQL:
                protocol = 'postgresql'
            elif ports[target_port] == Protocol.VNC:
                protocol = 'vnc'
            elif ports[target_port] == Protocol.X11:
                protocol = 'x11'
            time_ref = event_ref.child(
                str(int(time.time())))
            time_ref.update({
                "event_type" : "PORT Scan",
                "scan_type" : "FIN",
                "protocol" : protocol,
                "port" : target_port,
                "src_ip" : ip_field.src
            })
            
def port_null_scan_detect(packet : Packet, event_ref : db.Reference):
    protocol = ''
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
            elif ports[target_port] == Protocol.SMTP:
                protocol = 'smtp'
            elif ports[target_port] == Protocol.DNS:
                protocol = 'dns'
            elif ports[target_port] == Protocol.HTTP:
                protocol = 'http'
            elif ports[target_port] == Protocol.RPCBIND:
                protocol = 'rpcbind'
            elif ports[target_port] == Protocol.NETBIOS:
                protocol = 'netbios'
            elif ports[target_port] == Protocol.SMB:
                protocol = 'smb'
            elif ports[target_port] == Protocol.EXEC:
                protocol = 'exec'
            elif ports[target_port] == Protocol.LOGIN:
                protocol = 'login'
            elif ports[target_port] == Protocol.SHELL:
                protocol = 'shell'
            elif ports[target_port] == Protocol.CCPROXY:
                protocol = 'ccproxy'
            elif ports[target_port] == Protocol.MYSQL:
                protocol = 'mysql'
            elif ports[target_port] == Protocol.POSTGRESQL:
                protocol = 'postgresql'
            elif ports[target_port] == Protocol.VNC:
                protocol = 'vnc'
            elif ports[target_port] == Protocol.X11:
                protocol = 'x11'
            time_ref = event_ref.child(
                str(int(time.time())))
            time_ref.update({
                "event_type" : "PORT Scan",
                "scan_type" : "NULL",
                "protocol" : protocol,
                "port" : target_port,
                "src_ip" : ip_field.src
            })

def port_ack_scan_detect(packet : Packet, event_ref : db.Reference):
    protocol = ''
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
            elif ports[target_port] == Protocol.SMTP:
                protocol = 'smtp'
            elif ports[target_port] == Protocol.DNS:
                protocol = 'dns'
            elif ports[target_port] == Protocol.HTTP:
                protocol = 'http'
            elif ports[target_port] == Protocol.RPCBIND:
                protocol = 'rpcbind'
            elif ports[target_port] == Protocol.NETBIOS:
                protocol = 'netbios'
            elif ports[target_port] == Protocol.SMB:
                protocol = 'smb'
            elif ports[target_port] == Protocol.EXEC:
                protocol = 'exec'
            elif ports[target_port] == Protocol.LOGIN:
                protocol = 'login'
            elif ports[target_port] == Protocol.SHELL:
                protocol = 'shell'
            elif ports[target_port] == Protocol.CCPROXY:
                protocol = 'ccproxy'
            elif ports[target_port] == Protocol.MYSQL:
                protocol = 'mysql'
            elif ports[target_port] == Protocol.POSTGRESQL:
                protocol = 'postgresql'
            elif ports[target_port] == Protocol.VNC:
                protocol = 'vnc'
            elif ports[target_port] == Protocol.X11:
                protocol = 'x11'
            time_ref = event_ref.child(
                str(int(time.time())))
            time_ref.update({
                "event_type" : "PORT Scan",
                "scan_type" : "ACK",
                "protocol" : protocol,
                "port" : target_port,
                "src_ip" : ip_field.src
            })

def sniffPacket(packet : Packet, connect_ref : db.Reference):
    protocol = ''
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
            elif ports[target_port] == Protocol.SMTP:
                protocol = 'smtp'
            elif ports[target_port] == Protocol.DNS:
                protocol = 'dns'
            elif ports[target_port] == Protocol.HTTP:
                protocol = 'http'
            elif ports[target_port] == Protocol.RPCBIND:
                protocol = 'rpcbind'
            elif ports[target_port] == Protocol.NETBIOS:
                protocol = 'netbios'
            elif ports[target_port] == Protocol.SMB:
                protocol = 'smb'
            elif ports[target_port] == Protocol.EXEC:
                protocol = 'exec'
            elif ports[target_port] == Protocol.LOGIN:
                protocol = 'login'
            elif ports[target_port] == Protocol.SHELL:
                protocol = 'shell'
            elif ports[target_port] == Protocol.CCPROXY:
                protocol = 'ccproxy'
            elif ports[target_port] == Protocol.MYSQL:
                protocol = 'mysql'
            elif ports[target_port] == Protocol.POSTGRESQL:
                protocol = 'postgresql'
            elif ports[target_port] == Protocol.VNC:
                protocol = 'vnc'
            elif ports[target_port] == Protocol.X11:
                protocol = 'x11'
            time_ref = connect_ref.child(str(int(time.time())))
            time_ref.update({
                'protocol' : protocol,
                'l3_protocol' : "TCP",
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
            elif ports[target_port] == Protocol.SMTP:
                protocol = 'smtp'
            elif ports[target_port] == Protocol.DNS:
                protocol = 'dns'
            elif ports[target_port] == Protocol.HTTP:
                protocol = 'http'
            elif ports[target_port] == Protocol.RPCBIND:
                protocol = 'rpcbind'
            elif ports[target_port] == Protocol.NETBIOS:
                protocol = 'netbios'
            elif ports[target_port] == Protocol.SMB:
                protocol = 'smb'
            elif ports[target_port] == Protocol.EXEC:
                protocol = 'exec'
            elif ports[target_port] == Protocol.LOGIN:
                protocol = 'login'
            elif ports[target_port] == Protocol.SHELL:
                protocol = 'shell'
            elif ports[target_port] == Protocol.CCPROXY:
                protocol = 'ccproxy'
            elif ports[target_port] == Protocol.MYSQL:
                protocol = 'mysql'
            elif ports[target_port] == Protocol.POSTGRESQL:
                protocol = 'postgresql'
            elif ports[target_port] == Protocol.VNC:
                protocol = 'vnc'
            elif ports[target_port] == Protocol.X11:
                protocol = 'x11'
            time_ref = connect_ref.child(str(int(time.time())))
            time_ref.update({
                'protocol' : protocol,
                'l3_protocol' : "UDP",
                'ttl' : ip_field.ttl,
                'tos' : ip_field.tos,
                'src_address' : ip_field.src,
                'dst_address' : ip_field.dst,
                'src_port' : tcp_field.sport,
                'dst_port' : tcp_field.dport,
            })
