# reports/risk_score.py

class RiskScore:

    SEVERITY_WEIGHTS = {
        "INFO": 0,
        "LOW": 1,
        "MEDIUM": 3,
        "HIGH": 6,
        "CRITICAL": 10
    }

    def calculate(self, findings):
        total_score = 0

        for finding in findings:
            severity = finding.get("severity", "INFO")
            total_score += self.SEVERITY_WEIGHTS.get(severity, 0)

        return self._interpret_score(total_score)

    def _interpret_score(self, score):
        if score < 5:
            return "SECURE"

        if score < 15:
            return "MODERATE RISK"

        if score < 30:
            return "HIGH RISK"

        return "CRITICAL RISK"