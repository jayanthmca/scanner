from modules.basemodule import BaseModule
import re

class InjectionAudit(BaseModule):
    """
    Real-time InjectionAudit module.
    Detects both LLM prompt injections and SQL injection attempts.
    Works on any input passed via `inputs` or `context` (URL, query params, user input).
    """

    # 🔥 Patterns for prompt injection / malicious LLM instructions
    PROMPT_INJECTION_PATTERNS = [
        r"ignore previous rules",
        r"bypass security",
        r"override system",
        r"godmode",
        r"delete all",
        r"shutdown",
        r"format disk"
    ]

    # 🔥 Patterns for SQL injection
    SQL_INJECTION_PATTERNS = [
        r"union select",
        r"drop table",
        r"insert into",
        r"update .* set",
        r"delete from",
        r"--",           # SQL comment
        r";",            # query separator
        r"' or '1'='1",  # classic tautology
        r'" or "1"="1',
        r"or 1=1",
        r"exec\(",
        r"benchmark\("
    ]

    def analyze(self, inputs=None, context=None):
        """
        inputs: list of strings to scan (optional)
        context: dict containing live URL, query params, user input, etc.
        Returns a list of findings.
        """
        findings = []

        # Merge all items to scan
        scan_items = []
        if inputs:
            scan_items.extend(inputs)

        if context:
            for key, value in context.items():
                if isinstance(value, str):
                    scan_items.append(value)
                elif isinstance(value, list):
                    scan_items.extend([str(v) for v in value])
                elif isinstance(value, dict):
                    for sub_val in value.values():
                        scan_items.append(str(sub_val))

        # Scan all items for prompt injection
        for item in scan_items:
            for pattern in self.PROMPT_INJECTION_PATTERNS:
                if re.search(pattern, str(item), re.IGNORECASE):
                    findings.append({
                        "device": context.get("url", "LLM_INPUT") if context else "LLM_INPUT",
                        "severity": "HIGH",
                        "issue": "Prompt Injection Detected",
                        "details": f"Matched pattern: '{pattern}' in input: '{item}'"
                    })

            for pattern in self.SQL_INJECTION_PATTERNS:
                if re.search(pattern, str(item), re.IGNORECASE):
                    findings.append({
                        "device": context.get("url", "SQL_INPUT") if context else "SQL_INPUT",
                        "severity": "HIGH",
                        "issue": "SQL Injection Attempt Detected",
                        "details": f"Matched pattern: '{pattern}' in input: '{item}'"
                    })

        return findings