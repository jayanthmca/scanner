# sniffer.py
from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

def start_sniffer(interface):
    sniff(iface=interface, prn=packet_callback, store=False)