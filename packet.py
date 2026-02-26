from scapy.all import sniff, IP, TCP, UDP, ICMP
import json
from datetime import datetime
import threading

OUTPUT_FILE = "packet_log.json"
PACKET_LIMIT = 100
packet_data = []
lock = threading.Lock()

def classify_risk(packet_info):
    risk = "LOW"

    # Suspicious port usage
    suspicious_ports = [23, 445, 3389]
    if packet_info.get("dst_port") in suspicious_ports:
        risk = "MEDIUM"

    # Large packet anomaly
    if packet_info.get("length", 0) > 1500:
        risk = "HIGH"

    return risk

def process_packet(packet):
    if IP in packet:
        packet_info = {
            "timestamp": str(datetime.now()),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": packet[IP].proto,
            "length": len(packet)
        }

        if TCP in packet:
            packet_info.update({
                "protocol_name": "TCP",
                "src_port": packet[TCP].sport,
                "dst_port": packet[TCP].dport,
                "flags": str(packet[TCP].flags)
            })

        elif UDP in packet:
            packet_info.update({
                "protocol_name": "UDP",
                "src_port": packet[UDP].sport,
                "dst_port": packet[UDP].dport
            })

        elif ICMP in packet:
            packet_info.update({
                "protocol_name": "ICMP",
                "type": packet[ICMP].type,
                "code": packet[ICMP].code
            })

        packet_info["risk_level"] = classify_risk(packet_info)

        with lock:
            packet_data.append(packet_info)

        print(f"[{packet_info['risk_level']}] "
              f"{packet_info['protocol_name']} "
              f"{packet_info['src_ip']}:{packet_info.get('src_port', '')} "
              f"-> {packet_info['dst_ip']}:{packet_info.get('dst_port', '')}")

def save_to_json():
    with open(OUTPUT_FILE, "w") as f:
        json.dump(packet_data, f, indent=4)
    print(f"\n[+] Packet log saved to {OUTPUT_FILE}")

def start_sniffing():
    print("=" * 60)
    print("[+] Defensive Packet Analyzer Started")
    print(f"[+] Capturing {PACKET_LIMIT} packets")
    print("=" * 60)

    sniff(prn=process_packet, count=PACKET_LIMIT)
    save_to_json()

if __name__ == "__main__":
    start_sniffing()