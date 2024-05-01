import scapy.all as scapy
def sniff_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)
def process_packet(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        print(f"[*] New Packet: {src_ip} --> {dst_ip} Protocol: {protocol}")
        if packet.haslayer(scapy.TCP):
            payload = packet[scapy.Raw].load
            print(f"[*] TCP Data: {payload}")
        elif packet.haslayer(scapy.UDP):
            payload = packet[scapy.Raw].load
            print(f"[*] UDP Data: {payload}")
interface = "<interface>" 
sniff_packets(interface)
