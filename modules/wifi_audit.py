import subprocess
import re

class WifiAudit:

    DEFAULT_SSID_PATTERNS = [
        "TP-Link",
        "D-Link",
        "NETGEAR",
        "ACT",
        "Airtel",
        "JioFiber",
        "Huawei"
    ]

    def scan(self, context=None):import subprocess
import re

class WifiAudit:

    DEFAULT_SSID_PATTERNS = [
        "TP-Link",
        "D-Link",
        "NETGEAR",
        "ACT",
        "Airtel",
        "JioFiber",
        "Huawei"
    ]

    def scan(self, context=None):
        findings = []

        try:
            output = subprocess.check_output(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
        except Exception as e:
            print("Error running netsh:", e)
            return findings

        # Split SSID blocks
        ssids = re.split(r"\nSSID \d+ : ", output)[1:]

        for block in ssids:
            lines = block.split("\n")
            ssid = lines[0].strip()
            if not ssid:
                continue

            # Extract first BSSID (MAC) and encryption/auth info
            mac_matches = re.findall(r"BSSID \d+ *: ([\w:]+)", block)
            bssid = mac_matches[0] if mac_matches else "Unknown"

            auth_match = re.search(r"Authentication\s+:\s+(.*)", block)
            enc_match = re.search(r"Encryption\s+:\s+(.*)", block)

            auth = auth_match.group(1).strip() if auth_match else "Unknown"
            enc = enc_match.group(1).strip() if enc_match else "Unknown"

            # Base evaluation
            severity = "LOW"
            issue = "Secure configuration"

            if "Open" in auth:
                severity = "CRITICAL"
                issue = "Open WiFi network detected"
            elif "WEP" in auth:
                severity = "CRITICAL"
                issue = "WEP encryption detected (deprecated)"
            elif "WPA" in auth and "WPA3" not in auth:
                severity = "MEDIUM"
                issue = "WPA/WPA2 detected (check for legacy support)"

            # 🔥 SSID POLICY ENFORCEMENT
            policy_finding = self._check_ssid_policy(ssid)
            if policy_finding:
                severity = self._merge_severity(severity, policy_finding["severity"])
                issue += f"; {policy_finding['issue']}"

            findings.append({
                "device": ssid,
                "bssid": bssid,
                "severity": severity,
                "issue": issue,
                "details": f"{auth} / {enc}"
            })

        return findings

    def _check_ssid_policy(self, ssid):
        """
        Flags SSIDs that appear to be factory default.
        """
        for pattern in self.DEFAULT_SSID_PATTERNS:
            if pattern.lower() in ssid.lower():
                return {
                    "severity": "MEDIUM",
                    "issue": "SSID resembles factory default (verify credentials changed)"
                }
        return None

    def _merge_severity(self, base, new):
        """
        Merge two severity levels; returns the stricter one.
        CRITICAL > HIGH > MEDIUM > LOW
        """
        levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        base_index = levels.index(base) if base in levels else 0
        new_index = levels.index(new) if new in levels else 0
        return levels[max(base_index, new_index)]
        findings = []

        try:
            output = subprocess.check_output(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
        except Exception as e:
            print("Error running netsh:", e)
            return findings

        ssids = re.split(r"\nSSID \d+ : ", output)[1:]

        for block in ssids:
            lines = block.split("\n")
            ssid = lines[0].strip()
            if not ssid:
                continue

            auth_match = re.search(r"Authentication\s+:\s+(.*)", block)
            enc_match = re.search(r"Encryption\s+:\s+(.*)", block)

            auth = auth_match.group(1).strip() if auth_match else "Unknown"
            enc = enc_match.group(1).strip() if enc_match else "Unknown"

            # Base evaluation
            severity = "LOW"
            issue = "Secure configuration"

            if "Open" in auth:
                severity = "CRITICAL"
                issue = "Open WiFi network detected"
            elif "WEP" in auth:
                severity = "CRITICAL"
                issue = "WEP encryption detected (deprecated)"
            elif "WPA" in auth and "WPA3" not in auth:
                severity = "MEDIUM"
                issue = "WPA/WPA2 detected (check for legacy support)"

            # 🔥 SSID POLICY ENFORCEMENT
            policy_finding = self._check_ssid_policy(ssid)
            if policy_finding:
                # escalate severity if policy is stricter
                severity = self._merge_severity(severity, policy_finding["severity"])
                issue += f"; {policy_finding['issue']}"

            findings.append({
                "device": ssid,
                "severity": severity,
                "issue": issue,
                "details": f"{auth} / {enc}"
            })

        return findings

    def _check_ssid_policy(self, ssid):
        """
        Flags SSIDs that appear to be factory default.
        """
        for pattern in self.DEFAULT_SSID_PATTERNS:
            if pattern.lower() in ssid.lower():
                return {
                    "severity": "MEDIUM",
                    "issue": "SSID resembles factory default (verify credentials changed)"
                }
        return None

    def _merge_severity(self, base, new):
        """
        Merge two severity levels; returns the stricter one.
        CRITICAL > HIGH > MEDIUM > LOW
        """
        levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        base_index = levels.index(base) if base in levels else 0
        new_index = levels.index(new) if new in levels else 0
        return levels[max(base_index, new_index)]