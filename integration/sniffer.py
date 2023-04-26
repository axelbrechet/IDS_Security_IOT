import pyshark
import time
from dataclasses import dataclass

# Immutable data class
@dataclass(frozen=True)
class Packet():
    protocol    : int 
    length      : int
    srcport     : int
    dstport     : int
    timediff    : int 
    srcaddr     : int
    dstaddr     : int

class Sniffer:

    def __init__(self, iface):
        self.capture = pyshark.LiveCapture(interface=iface)
        self.last_pkt_time = None

    def run(self, callback):
        for raw_pkt in self.capture.sniff_continuously():
            if not (self.filter(raw_pkt)): continue
            pkt = self.build_packet(raw_pkt)
            self.last_pkt_time = time.time()
            callback(pkt)
            
    def filter(self, raw_pkt):
        is_ipv4 = raw_pkt.eth.type == '0x0800'
        is_ipv6 = raw_pkt.eth.type == '0x86dd'
        is_tcp = raw_pkt.transport_layer == 'TCP'
        return is_ipv4 and is_tcp

    def build_packet(self, raw_pkt):
        return Packet(
            raw_pkt.ip.src.hex_value,
            raw_pkt.ip.dst.hex_value,
            len(raw_pkt),
            raw_pkt.ip.proto.hex_value,
            raw_pkt.tcp.srcport.hex_value,
            raw_pkt.tcp.dstport.hex_value,
            0 if self.last_pkt_time is None else time.time() - self.last_pkt_time,
        )