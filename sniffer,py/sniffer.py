from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    # Analyze packets that contain an IP layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        # Determine protocol type
        protocol_name = "Other"
        if packet.haslayer(TCP):
            protocol_name = "TCP"
        elif packet.haslayer(UDP):
            protocol_name = "UDP"

        print(f"\n[+] New Packet Captured:")
        print(f"    - Source IP     : {src_ip}")
        print(f"    - Destination IP: {dst_ip}")
        print(f"    - Protocol      : {protocol_name} ({proto})")

        # Extract payload data if present
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"    - Payload       : {payload[:50]}...")  # Display first 50 bytes

def main():
    print("=== Network Sniffer Started ===")
    print("Capturing packets... Press Ctrl+C to stop.\n")
    
    # Start capturing network packets (store=0 prevents high memory usage)
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()