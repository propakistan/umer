from scapy.all import sniff

from scapy.layers.inet import IP, TCP, UDP

def packet_analysis(packet):

 if IP in packet:

 ip_src = packet[IP].src

 ip_dst = packet[IP].dst

protocol = packet[IP].proto

        if protocol == 6 and TCP in packet:


  src_port = packet[TCP].sport

 dst_port = packet[TCP].dport

 print(f"TCP Packet from {ip_src}:{src_port} to {ip_dst}:{dst_port}")

 elif protocol == 17 and UDP in packet:

  src_port = packet[UDP].sport

            dst_port = packet[UDP].dport

            print(f"UDP Packet from {ip_src}:{src_port} to {ip_dst}:{dst_port}")

# Sniff network packets

print("Starting packet capture...")

sniff(filter="ip", prn=packet_analysis, count=10)

print("Packet capture complete.")

