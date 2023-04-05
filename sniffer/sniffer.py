import pyshark
import csv
from dataclasses import dataclass

# Immutable data class
@dataclass(frozen=True)
class Packet():
    srcaddr : int # IPV4 source address (decimal integers)
    dstaddr : int # IPV4 destination address (decimal integers)
    type    : int # Layer 3 protocol (decimal integers) => IPV4:0x0800=2048
    length  : int

class Sniffer:

    CAPTURE_TIMEOUT_SEC = 10
    OUTPUT_CSV_PATH = 'output.csv'

    def __init__(self, iface, buffer_size=20):
        self.capture = pyshark.LiveCapture(interface=iface)
        self.buffer = Buffer(buffer_size)

    def run(self):
        while True:
            self.capture.sniff(timeout=Sniffer.CAPTURE_TIMEOUT_SEC)
            packets = filter(self.filter, self.capture._packets)
            with open(Sniffer.OUTPUT_CSV_PATH, mode='w', newline='', encoding='utf-8') as output_csv:
                writer = csv.writer(output_csv)
                self.write_header_to_csv(writer)
                for raw_pkt in packets:
                    pkt = self.build_packet(raw_pkt)
                    self.write_packet_to_csv(pkt, writer)
            self.clear_packets()

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
            len(raw_pkt)
        )
    
    def clear_packets(self):
        self.capture._packets.clear()

    def write_header_to_csv(self, writer):
        writer.writerow(Packet.__annotations__.keys())

    def write_packet_to_csv(self, pkt, writer):
        pkt_attrs = list(vars(pkt).values())
        writer.writerow(pkt_attrs)
    
sniffer = Sniffer('\\Device\\NPF_{718ADC81-1EAC-4ED0-835F-1E96B7DF7076}', 10)
sniffer.run()

