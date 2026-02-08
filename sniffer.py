from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import Counter
from datetime import datetime

protocol_count = Counter()

def analyze_packet(packet):
    time = datetime.now().strftime("%H:%M:%S")

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst

        print(f"\n[{time}] Packet Captured")
        print(f"Source IP      : {src}")
        print(f"Destination IP : {dst}")

        if TCP in packet:
            protocol_count["TCP"] += 1
            print("Protocol       : TCP")
            print(f"Src Port       : {packet[TCP].sport}")
            print(f"Dst Port       : {packet[TCP].dport}")ss

        elif UDP in packet:
            protocol_count["UDP"] += 1
            print("Protocol       : UDP")
            print(f"Src Port       : {packet[UDP].sport}")
            print(f"Dst Port       : {packet[UDP].dport}")

        elif ICMP in packet:
            protocol_count["ICMP"] += 1
            print("Protocol       : ICMP")

        else:
            protocol_count["Other"] += 1
            print("Protocol       : Other")

print("Starting Network Sniffer...")
print("Capturing packets infinitely (Press CTRL+C to stop)\n")

try:
    sniff(prn=analyze_packet)
except KeyboardInterrupt:
    print("\nSniffer stopped by user")

print("\n========== Traffic Summary ==========")
for proto, count in protocol_count.items():
    print(f"{proto} packets : {count}")
print("=====================================")

