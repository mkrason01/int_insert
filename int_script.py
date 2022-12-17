import scapy 
from scapy.all import *

class UDPshim(Packet) :
    fields_desc = [
            BitField("Type", 0, 4), 
            BitField("R1", 0, 1),
            BitField("R2",0, 1),
            BitField("NPT", 0, 2),
            BitField("Length", 0, 8),
            BitField("UDP_PORT", 0, 16)
            ]
class main_headers(Packet):
    fields_desc = []
class UDP_INT_HEADER(Packet) :
    fields_desc = []
class INT_METADANE(Packet):
    fields_desc = []
if __name__ == "__main__" :
    #pkt = bytes([0 for i in range(1000)])
    #x = main_headers(pkt[0:do_konca_headera1])
    #udp_payload = pkt[do_konca_header1:]
    #shim = UDPshim()
    #przypisz tu dane do shima
    #header = UDP_INT_HEADER()
    #znowu przypisz tu dane
    #metadane = INT_METADANE()
    #znowu przypisz dane
    packet = Packet()
    z = UDPshim()
    #packet /=z
    #packet /=z
    packet.show()
    packet /=x







