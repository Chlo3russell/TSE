def detect_syn_flood(packet, traffic_data):
    if packet[TCP].flags == "S":  # SYN flag
        traffic_data["alerts"].append(f"SYN flood detected from {packet[IP].src} to {packet[IP].dst}")

def detect_high_packet_rate(traffic_data, threshold, window):
    packet_rate = traffic_data["total_packets"] / window
    if packet_rate > threshold:
        traffic_data["alerts"].append(f"High packet rate detected: {packet_rate} packets/sec")
