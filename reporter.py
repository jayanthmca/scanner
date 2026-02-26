# reporter.py
import json
from datetime import datetime

def generate_report(target, open_ports):
    report = {
        "target": target,
        "time": str(datetime.now()),
        "open_ports": open_ports
    }
    with open("report.json", "w") as f:
        json.dump(report, f, indent=4)