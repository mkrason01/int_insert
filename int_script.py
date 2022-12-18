import scapy 
from scapy.all import *

interfaces = ["test2", "test3"]

class main_headers(Packet):
    fields_desc = []
class UDPshim(Packet) :
    fields_desc = [
            BitField("Type", 1, 4), 
            BitField("NPT", 1, 2),
            BitField("R1", 0, 1),
            BitField("R2",0, 1),
            BitField("Length", 7, 8),
            BitField("UDP_PORT", 17, 16) 
            #kiedys uzupelnic UDP_PORT
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
    #pkt = bytes([0 for i in range(1000)])
    pkt2 = bytes(pkt)
    print("1 worked")
    x = main_headers(pkt2[0:42])
    print("------------",len(pkt2),type(pkt2),"--------------")
    print(x)
    print("2 worked")
    print("------------",len(bytes(x)),"--------------")
    udp_payload = pkt2[42:]
    print("------------",len(udp_payload),"--------------")
    print("3 worked")
    shim = UDPshim()
    #przypisz tu dane do shima
    header = UDP_INT_HEADER()
    #znowu przypisz tu dane
    metadane = INT_METADANE()
    print("===================", len(bytes(metadane)), "================")
    #znowu przypisz dane
    packet = Packet()
    print("4 worked")
    z = UDPshim()
    packet /= x
    packet /= shim
    packet /= header
    packet /= metadane
    packet /= udp_payload
    print("5 worked")
    #print(len(bytes(packet)))
    print("7 worked")
    #print(packet.show())
    #print("=================", bytes(packet), "==================")
    sendp(packet, iface=interfaces[1])
    print("6 worked")

def forward_and_change_2(pkt) :
    pkt = bytearray(bytes(pkt))
    newPacket = pkt[:42]
    payload = pkt[42:]
    shim = UDPshim()
    intheader = UDP_INT_HEADER()
    newPacket.extend(bytes(shim))
    newPacket.extend(bytes(intheader))
    newPacket.extend(payload)
    print(len(newPacket),"==================================================")
    sendp(bytes(newPacket), iface=interfaces[1])




sniff(iface=interfaces[0], prn=forward_and_change_2)






