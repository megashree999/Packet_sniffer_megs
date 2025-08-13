import scapy.all as scapy

packets = []

def process_packet(packet):
    print("\n--- Packet Captured ---")
    if packet.haslayer(scapy.Ether):
        eth = packet[scapy.Ether]
        print(f"Ethernet: src={eth.src}, dst={eth.dst}, type={hex(eth.type)}")
    if packet.haslayer(scapy.IP):
        ip = packet[scapy.IP]
        print(f"IPv4: src={ip.src}, dst={ip.dst}, version={ip.version}, ttl={ip.ttl}, protocol={ip.proto}")
    if packet.haslayer(scapy.IPv6):
        ipv6 = packet[scapy.IPv6]
        print(f"IPv6: src={ipv6.src}, dst={ipv6.dst}, version={ipv6.version}, hlim={ipv6.hlim}, nh={ipv6.nh}")
    if packet.haslayer(scapy.TCP):
        tcp = packet[scapy.TCP]
        print(f"TCP: sport={tcp.sport}, dport={tcp.dport}, flags={tcp.flags}, seq={tcp.seq}")
    if packet.haslayer(scapy.UDP):
        udp = packet[scapy.UDP]
        print(f"UDP: sport={udp.sport}, dport={udp.dport}, len={udp.len}")
    print("----------------------")

    packets.append(packet)

def get_filter():
    print("Enter protocols to filter (comma separated), options: tcp, udp, icmp, arp, ip")
    print("Leave blank for no filter (capture all)")
    user_input = input("Protocols to filter: ").strip().lower()

    if not user_input:
        return ""  # No filter

    protocols = [p.strip() for p in user_input.split(",")]
    # Build BPF filter string for scapy sniff()
    filters = []
    for p in protocols:
        if p in ["tcp", "udp", "icmp", "arp", "ip"]:
            filters.append(p)
        else:
            print(f"Ignoring unknown protocol: {p}")

    return " or ".join(filters)

def main():
    iface = input("Enter interface name (e.g. Wi-Fi): ").strip()
    bpf_filter = get_filter()

    print(f"\nStarting packet capture on interface '{iface}' with filter '{bpf_filter}'")
    print("Press Ctrl+C to stop and save packets...")

    try:
        scapy.sniff(iface=iface, filter=bpf_filter, store=False, prn=process_packet)
    except KeyboardInterrupt:
        print("\nStopping capture...")

    # Save captured packets to pcap file
    scapy.wrpcap("captured_packets.pcap", packets)
    print("Saved packets to captured_packets.pcap")

if __name__ == "__main__":
    main()
