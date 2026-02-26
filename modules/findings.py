class Finding:

    def __init__(self, device, severity, issue, details, context=None):
        self.device = device
        self.severity = severity
        self.issue = issue
        self.details = details

    def to_dict(self, context=None):
        return {
            "device": self.device,
            "severity": self.severity,
            "issue": self.issue,
            "details": self.details
        }