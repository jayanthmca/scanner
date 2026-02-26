class ConfigAudit:

    def analyze(self, devices, context=None):
        findings = []

        if not devices:
            return findings

        for device in devices:
            device_name = device.get("name", "Unknown Device")
            default_pass = device.get("default_password", False)

            if default_pass:
                findings.append({
                    "device": device_name,
                    "severity": "HIGH",
                    "issue": "Default credentials detected",
                    "details": f"Device {device_name} is using default username/password"
                })
            else:
                # Optional: add low-level check info
                findings.append({
                    "device": device_name,
                    "severity": "LOW",
                    "issue": "Credentials changed",
                    "details": f"Device {device_name} does not use default credentials"
                })

        return findings