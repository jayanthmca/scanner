import asyncio
import json
import argparse
import sqlite3
from datetime import datetime, timezone
from bleak import BleakScanner, BleakClient
from bleak.exc import BleakDeviceNotFoundError
import traceback

SQLITE_DB_FILE = "bluetooth_cves.db"


class BluetoothDefensiveScanner:

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.conn = sqlite3.connect(SQLITE_DB_FILE)
        self.conn.row_factory = sqlite3.Row

    # -------------------------------------------------
    # Device Discovery
    # -------------------------------------------------
    async def discover_devices(self):
        print("[*] Scanning for Bluetooth LE devices...")

        raw_devices = await BleakScanner.discover(
            timeout=self.timeout,
            return_adv=True
        )

        devices = []

        for address, (device, adv) in raw_devices.items():
            devices.append({
                "ble_device": device,
                "name": device.name or "Unknown",
                "address": device.address,
                "rssi": adv.rssi
            })

        return devices

    # -------------------------------------------------
    # Fingerprinting (Windows Safe)
    # -------------------------------------------------
    async def fingerprint_device(self, ble_device):
        print(f"[*] Fingerprinting {ble_device.address}")

        profile = {
            "services": [],
            "characteristics": []
        }

        try:
            async with BleakClient(ble_device, timeout=10.0) as client:

                # In Bleak 1.x services are populated automatically
                services = client.services

                if not services:
                    print(f"[!] No services discovered for {ble_device.address}")
                    return profile

                for service in services:
                    profile["services"].append(str(service.uuid))

                    for char in service.characteristics:
                        profile["characteristics"].append(str(char.uuid))

        except BleakDeviceNotFoundError:
            print(f"[!] Device {ble_device.address} disappeared.")
        except asyncio.TimeoutError:
            print(f"[!] Timeout connecting to {ble_device.address}")
        except Exception as e:
            print(f"[!] Enumeration error {ble_device.address}: {e}")

        return profile

    # -------------------------------------------------
    # SQLite CVE Matching
    # -------------------------------------------------
    def match_cves(self, fingerprint):
        cur = self.conn.cursor()
        matched = []

        # Basic Bluetooth keyword filter
        cur.execute("""
            SELECT id, description, cvss, published
            FROM cves
            WHERE description LIKE '%bluetooth%'
        """)

        rows = cur.fetchall()

        for row in rows:
            description_lower = row["description"].lower()

            # Try matching service UUID fragments
            match_found = False
            for service in fingerprint["services"]:
                if service[:8].lower() in description_lower:
                    match_found = True
                    break

            if match_found:
                matched.append(dict(row))
            else:
                # Optional: include generic Bluetooth CVEs
                matched.append(dict(row))

        return matched

    # -------------------------------------------------
    # Risk Score
    # -------------------------------------------------
    def risk_score(self, matched_cves):
        score = 0.0
        for cve in matched_cves:
            if cve["cvss"]:
                score += float(cve["cvss"])
        return round(score, 2)

    # -------------------------------------------------
    # Report Generation
    # -------------------------------------------------
    def generate_report(self, device, fingerprint, matched_cves, score):
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "device": {
                "name": device["name"],
                "address": device["address"],
                "rssi": device["rssi"]
            },
            "services_detected": fingerprint["services"],
            "matched_cves_count": len(matched_cves),
            "vulnerabilities": matched_cves,
            "aggregate_risk_score": score,
            "recommendation": (
                "Patch firmware, enforce LE Secure Connections, "
                "disable legacy pairing, restrict discoverability."
            )
        }

    # -------------------------------------------------
    def close(self):
        self.conn.close()


# =====================================================
# MAIN
# =====================================================
async def main():
    parser = argparse.ArgumentParser(
        description="Defensive Bluetooth Vulnerability Scanner (SQLite-backed)"
    )
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--output", default="report.json")
    args = parser.parse_args()

    scanner = BluetoothDefensiveScanner(timeout=args.timeout)

    devices = await scanner.discover_devices()

    all_reports = []

    for device in devices:
        fingerprint = await scanner.fingerprint_device(device["ble_device"])
        matched = scanner.match_cves(fingerprint)
        score = scanner.risk_score(matched)
        report = scanner.generate_report(device, fingerprint, matched, score)
        all_reports.append(report)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(all_reports, f, indent=4)

    scanner.close()

    print(f"[+] Scan complete. Report saved to {args.output}")


if __name__ == "__main__":
    asyncio.run(main())