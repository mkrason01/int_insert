import scapy
from scapy.all import *
def forward_and_change_2(pkt) :
    print("len pkt: ",len(pkt))

sniff(iface="test4", prn=forward_and_change_2)
