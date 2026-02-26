class SecurityEngine:

    def __init__(self, modules, risk):
        self.modules = modules
        self.risk = risk

    def run(self, context=None):
        """
        context: dict with keys like 'url', 'targets', etc.
        """
        findings = {}
        context = context or {}

        # Collect phase
        for module in self.modules:
            if hasattr(module, "collect"):
                data = module.collect(context)
                if data:
                    findings[module.__class__.__name__] = data

        # Scan phase
        for module in self.modules:
            if hasattr(module, "scan"):
                scan_results = module.scan(context)
                findings.setdefault(module.__class__.__name__, []).extend(scan_results)

        # Analyze phase
        for module in self.modules:
            if hasattr(module, "analyze"):
                for key, value in findings.items():
                    results = module.analyze(value, context)
                    findings[key].extend(results)

        # Flatten all findings
        all_findings = []
        for k, v in findings.items():
            all_findings.extend(v)

        score = self.risk.calculate(all_findings)
        return score, all_findings