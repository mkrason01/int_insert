import scapy 
from scapy.all import *

interfaces = ["veth-output", "enp0s3"]

class main_headers(Packet):
    fields_desc = []
class UDPshim(Packet) :
    fields_desc = [
            BitField("Type", 1, 1), 
            BitField("NPT", 1, 2),
            BitField("R1", 0, 1),
            BitField("R2",0, 1),
            BitField("Length", 7, 8),
            BitField("UDP_PORT", NWM, 16)
            ]

class UDP_INT_HEADER(Packet) :
    fields_desc = [
            BitField("Version", 2, 4),
            BitField("D", 0, 1),
            BitField("E", 0, 1),
            BitField("M", 0, 1),
            BitField("R", 0, 12),
            BitField("HopML", 2, 5),
            BitField("RemainingHopC", 6, 8),
            BitField("InstructBitmap", 36864, 16),
            BitField("DomSpecificID", 0, 16),
            BitField("DSInstr", 0, 16),
            BitField("DSFlags", 0, 16),


    ]
class INT_METADANE(Packet):
    fields_desc = []

def forward_and_change(pkt) :
    pkt = bytes([0 for i in range(64)])
    x = main_headers(pkt[0:41])
    udp_payload = pkt[41:]
    shim = UDPshim()
    #przypisz tu dane do shima
    header = UDP_INT_HEADER()
    #znowu przypisz tu dane
    metadane = INT_METADANE()
    #znowu przypisz dane
    packet = Packet()
    z = UDPshim()
    packet /=x
    packet /=shim
    packet /=header
    packet /=metadane
    packet /=udp_payload
    print(pkt.show())
    sendp(pkt, iface=interfaces[1])
sniff(iface=interfaces[0], prn=forward_and_change)






