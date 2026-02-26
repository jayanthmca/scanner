import requests

class WebAudit:

    def scan(self, context=None):
        findings = []
        url = context.get("url") if context else None

        if not url:
            return findings

        findings += self._check_cors(url)
        findings += self._check_robots(url)
        findings += self._check_security_headers(url)
        findings += self._check_http_methods(url)

        return findings

    # -----------------------------------------
    # 1️⃣ CORS Misconfiguration Check
    # -----------------------------------------
    def _check_cors(self, url):
        findings = []
        try:
            headers = {
                "Origin": "https://evil.com"
            }
            r = requests.get(url, headers=headers, timeout=5)

            acao = r.headers.get("Access-Control-Allow-Origin")

            if acao == "*" or acao == "https://evil.com":
                findings.append({
                    "device": url,
                    "severity": "HIGH",
                    "issue": "CORS misconfiguration",
                    "details": f"Access-Control-Allow-Origin set to: {acao}"
                })
        except Exception:
            pass

        return findings

    # -----------------------------------------
    # 2️⃣ robots.txt Exposure
    # -----------------------------------------
    def _check_robots(self, url):
        findings = []
        try:
            robots_url = url.rstrip("/") + "/robots.txt"
            r = requests.get(robots_url, timeout=5)

            if r.status_code == 200 and "Disallow" in r.text:
                findings.append({
                    "device": url,
                    "severity": "INFO",
                    "issue": "robots.txt exposed",
                    "details": "Review disallowed paths for sensitive endpoints"
                })
        except Exception:
            pass

        return findings

    # -----------------------------------------
    # 3️⃣ Security Headers Check
    # -----------------------------------------
    def _check_security_headers(self, url):
        findings = []
        try:
            r = requests.get(url, timeout=5)
            headers = r.headers

            required_headers = [
                "X-Frame-Options",
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "Strict-Transport-Security"
            ]

            for header in required_headers:
                if header not in headers:
                    findings.append({
                        "device": url,
                        "severity": "MEDIUM",
                        "issue": f"Missing security header: {header}",
                        "details": "Header not found in response"
                    })
        except Exception:
            pass

        return findings

    # -----------------------------------------
    # 4️⃣ HTTP Methods Check
    # -----------------------------------------
    def _check_http_methods(self, url):
        findings = []
        try:
            r = requests.options(url, timeout=5)
            allow = r.headers.get("Allow")

            if allow:
                dangerous = ["PUT", "DELETE", "TRACE"]
                for method in dangerous:
                    if method in allow:
                        findings.append({
                            "device": url,
                            "severity": "HIGH",
                            "issue": f"Dangerous HTTP method enabled: {method}",
                            "details": f"Allow header: {allow}"
                        })
        except Exception:
            pass

        return findings