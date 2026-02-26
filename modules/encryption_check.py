class EncryptionCheck:

    def analyze(self, devices, context=None):
        findings = []

        for device in devices:
            if device.get("encryption") in ["WEP", "WPA"]:
                findings.append({
                    "device": device["name"],
                    "severity": "HIGH",
                    "issue": "Weak WiFi encryption detected"
                })

        return findings