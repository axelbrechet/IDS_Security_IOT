import pyshark
from dataclasses import dataclass

# Immutable data class
@dataclass(frozen=True)
class Packet():
    srcaddr : str
    dstaddr : str
    type    : str
    length  : int

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

    def add(self, elem):
        self.buffer[self.idx] = elem
        self.idx = (self.idx + 1) % self.size

class Sniffer:

    def __init__(self, iface, buffer_size=20):
        self.capture = pyshark.LiveCapture(interface=iface)
        self.buffer = Buffer(buffer_size)

    def run(self):
        for raw_pkt in self.capture.sniff_continuously():
            if not self.filter(raw_pkt): continue
            pkt = self.build_packet(raw_pkt)
            print(pkt)
            #self.buffer.add(pkt)
            #print(self.buffer)

    def filter(self, raw_pkt):
        is_ipv4 = raw_pkt.eth.type == '0x0800'
        is_ipv6 = raw_pkt.eth.type == '0x86dd'
        is_tcp = raw_pkt.transport_layer == 'TCP'
        return is_ipv4 and is_tcp

    def build_packet(self, raw_pkt):
        return Packet(
            raw_pkt.ip.src,
            raw_pkt.ip.dst,
            raw_pkt.eth.type,
            len(raw_pkt)
        )
    
sniffer = Sniffer('\\Device\\NPF_{718ADC81-1EAC-4ED0-835F-1E96B7DF7076}', 10)
sniffer.run()

