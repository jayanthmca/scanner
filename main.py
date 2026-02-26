from core.security_engine import SecurityEngine
from modules.device_inventory import DeviceInventory
from modules.config_audit import ConfigAudit
from modules.encryption_check import EncryptionCheck
from modules.wifi_audit import WifiAudit
from modules.redteammodule import RedTeamModule
from modules.injectionaudit import InjectionAudit
from modules.webaudit import WebAudit
from reports.risk_score import RiskScore
import html

def create_modules():
    return [
        WebAudit(),
        RedTeamModule(),
        InjectionAudit(),
        WifiAudit(),
        ConfigAudit(),
        EncryptionCheck()
    ]

def run_security_scan(urls):
    modules = create_modules()
    risk_calculator = RiskScore()
    engine = SecurityEngine(modules=modules, risk=risk_calculator)

    results = {}
    for url in urls:
        context = {"url": url}  # pass URL to each module
        score, findings = engine.run(context=context)
        results[url] = {"score": score, "findings": findings}
    return results

def display_results(results):
    for url, data in results.items():
        print(f"\n--- Results for: {url} ---")
        print(f"RISK SCORE: {data['score']}")
        for f in data["findings"]:
            print(f)

def export_results_to_dashboard(results, output_file="scan_dashboard.html"):
    html_content = """
    <html>
    <head>
        <title>Security Scan Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f0f2f5; margin: 0; padding: 0; }
            h1 { text-align: center; padding: 20px; background: #333; color: #fff; margin: 0; }
            h2 { color: #333; margin: 20px 0 5px 20px; }
            table { border-collapse: collapse; width: 95%; margin: 10px auto 30px auto; background: #fff; box-shadow: 0 2px 8px rgba(0,0,0,0.1);}
            th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
            th { background: #444; color: #fff; }
            tr:nth-child(even) { background: #f9f9f9; }
            .severity-badge { padding: 4px 8px; border-radius: 4px; color: #fff; font-weight: bold; text-align: center; display: inline-block; }
            .CRITICAL { background: #e74c3c; }
            .HIGH { background: #e67e22; }
            .MEDIUM { background: #f1c40f; color: #000; }
            .LOW { background: #2ecc71; }
            .INFO { background: #3498db; }
        </style>
    </head>
    <body>
        <h1>Security Scan Dashboard</h1>
    """

    for url, data in results.items():
        html_content += f"<h2>URL: {html.escape(url)}</h2>"
        html_content += f"<p><strong>RISK SCORE:</strong> {data['score']}</p>"
        html_content += "<table>"
        html_content += "<tr><th>Device / Target</th><th>BSSID / Identifier</th><th>Severity</th><th>Issue</th><th>Details</th></tr>"

        for f in data["findings"]:
            severity_class = f.get("severity", "INFO")
            html_content += "<tr>"
            html_content += f"<td>{html.escape(str(f.get('device','')))}</td>"
            html_content += f"<td>{html.escape(str(f.get('bssid','')))}</td>"
            html_content += f"<td><span class='severity-badge {severity_class}'>{severity_class}</span></td>"
            html_content += f"<td>{html.escape(str(f.get('issue','')))}</td>"
            html_content += f"<td>{html.escape(str(f.get('details','')))}</td>"
            html_content += "</tr>"

        html_content += "</table>"

    html_content += "</body></html>"

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"Dashboard exported to {output_file}")

def main():
    urls_to_scan = [
        "https://allstack.ai",
        # Add more URLs here
    ]
    results = run_security_scan(urls_to_scan)
    display_results(results)
    export_results_to_dashboard(results, output_file="scan_report.html")

if __name__ == "__main__":
    main()