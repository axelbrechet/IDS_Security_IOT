import pyshark
import time
from dataclasses import dataclass

# Circular Buffer
class Buffer():

    def __init__(self, size):
        self.size = size
        self.buffer = [None] * size
        self.idx = 0

    def __iter__(self):
        idx = 0
        while idx < self.size:
            yield self.buffer[idx]
            idx += 1

    def __str__(self):
        result = '-' * 15 + '\n'
        for idx, item in enumerate(self.buffer):
            result += f'{idx}: {item}\n'
        result += '-' * 15 + '\n'
        return result

    def is_full(self):
        return self.buffer[self.size-1] is not None

    def add(self, elem):
        self.buffer[self.idx] = elem
        self.idx = (self.idx + 1) % self.size

# Immutable data class
@dataclass(frozen=True)
class Packet():
    srcaddr : int # IPV4 source address (decimal integers)
    dstaddr : int # IPV4 destination address (decimal integers)
    type    : int # Layer 3 protocol (decimal integers) => IPV4:0x0800=2048
    length  : int
    time    : int 
    srcport : int
    dstport : int

class Sniffer:

    BUFFER_SIZE = 9 # Should be equal to the time_steps in the model

    def __init__(self, iface):
        self.capture = pyshark.LiveCapture(interface=iface)
        self.buffer = Buffer(Sniffer.BUFFER_SIZE)

    def run(self, callback):
        for raw_pkt in self.capture.sniff_continuously():
            if not (self.filter(raw_pkt)): continue
            pkt = self.build_packet(raw_pkt)
            self.buffer.add(pkt)
            if self.buffer.is_full(): 
                callback(self.buffer)
            
    def filter(self, raw_pkt):  
        is_ipv4 = raw_pkt.eth.type == '0x0800'
        is_ipv6 = raw_pkt.eth.type == '0x86dd'
        is_tcp = raw_pkt.transport_layer == 'TCP'
        return is_ipv4 and is_tcp

    def build_packet(self, raw_pkt):
        return Packet(
            raw_pkt.ip.src.hex_value,
            raw_pkt.ip.dst.hex_value,
            raw_pkt.eth.type.hex_value,
            len(raw_pkt),
            int(time.time()),
            raw_pkt.tcp.srcport.hex_value,
            raw_pkt.tcp.dstport.hex_value,
        )