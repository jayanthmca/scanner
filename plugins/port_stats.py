# plugins/port_stats.py

def run(open_ports):
    result = {}

    common_ports = {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        135: "RPC",
        139: "NetBIOS",
        443: "HTTPS",
        445: "SMB"
    }

    for port in open_ports:
        service = common_ports.get(port, "Unknown")
        result[port] = service

    return result