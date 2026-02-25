import json
import os
from datetime import datetime

REPORT_FILE = "report.json"
DASHBOARD_FILE = "dashboard.html"

def generate_dashboard():
    if not os.path.exists(REPORT_FILE):
        print(f"Error: {REPORT_FILE} not found. Run the scanner first.")
        return

    with open(REPORT_FILE, "r") as f:
        reports = json.load(f)

    # Calculate statistics
    total_devices = len(reports)
    total_cves = sum(r.get("matched_cves_count", 0) for r in reports)
    high_risk_devices = sum(1 for r in reports if r.get("aggregate_risk_score", 0) > 50)
    
    # Sort devices by risk score
    sorted_reports = sorted(reports, key=lambda x: x.get("aggregate_risk_score", 0), reverse=True)

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Defensive Bluetooth Insights</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg-color: #0a0b10;
            --card-bg: rgba(255, 255, 255, 0.05);
            --accent-color: #00d2ff;
            --risk-high: #ff4b2b;
            --risk-med: #ffaf40;
            --risk-low: #2ecc71;
            --text-primary: #ffffff;
            --text-secondary: #a0a0a0;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            background-color: var(--bg-color);
            color: var(--text-primary);
            font-family: 'Outfit', sans-serif;
            line-height: 1.6;
            overflow-x: hidden;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }}

        header {{
            text-align: center;
            margin-bottom: 60px;
            animation: fadeInDown 1s ease-out;
        }}

        h1 {{
            font-size: 3rem;
            font-weight: 700;
            background: linear-gradient(to right, #00d2ff, #3a7bd5);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }}

        .subtitle {{
            color: var(--text-secondary);
            font-size: 1.2rem;
            letter-spacing: 1px;
        }}

        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}

        .stat-card {{
            background: var(--card-bg);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 30px;
            border-radius: 20px;
            backdrop-filter: blur(10px);
            text-align: center;
            transition: transform 0.3s ease;
        }}

        .stat-card:hover {{
            transform: translateY(-5px);
            border-color: var(--accent-color);
        }}

        .stat-value {{
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--accent-color);
            display: block;
        }}

        .stat-label {{
            color: var(--text-secondary);
            text-transform: uppercase;
            font-size: 0.8rem;
            margin-top: 5px;
        }}

        /* Main Section */
        .main-layout {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 30px;
        }}

        .device-list {{
            display: flex;
            flex-direction: column;
            gap: 20px;
        }}

        .device-card {{
            background: var(--card-bg);
            border-left: 5px solid transparent;
            border-radius: 15px;
            padding: 25px;
            position: relative;
            animation: slideInLeft 0.5s ease-out forwards;
        }}

        .risk-high {{ border-left-color: var(--risk-high); }}
        .risk-med {{ border-left-color: var(--risk-med); }}
        .risk-low {{ border-left-color: var(--risk-low); }}

        .device-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}

        .device-name {{
            font-size: 1.4rem;
            font-weight: 600;
        }}

        .risk-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 700;
            text-transform: uppercase;
        }}

        .badge-high {{ background: rgba(255, 75, 43, 0.2); color: var(--risk-high); }}
        .badge-med {{ background: rgba(255, 175, 64, 0.2); color: var(--risk-med); }}
        .badge-low {{ background: rgba(46, 204, 113, 0.2); color: var(--risk-low); }}

        .device-details {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            font-size: 0.9rem;
            color: var(--text-secondary);
        }}

        .vulnerability-toggle {{
            margin-top: 15px;
            background: none;
            border: 1px solid var(--accent-color);
            color: var(--accent-color);
            padding: 8px 15px;
            border-radius: 5px;
            cursor: pointer;
            font-family: inherit;
            transition: all 0.3s ease;
        }}

        .vulnerability-toggle:hover {{
            background: var(--accent-color);
            color: var(--bg-color);
        }}

        /* Insights Sidebar */
        .insights-sidebar {{
            position: sticky;
            top: 20px;
            height: fit-content;
        }}

        .insight-box {{
            background: linear-gradient(135deg, rgba(0, 210, 255, 0.1), rgba(58, 123, 213, 0.1));
            border: 1px solid rgba(0, 210, 255, 0.2);
            padding: 25px;
            border-radius: 20px;
            margin-bottom: 20px;
        }}

        .insight-box h3 {{
            margin-bottom: 15px;
            color: var(--accent-color);
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .insight-item {{
            margin-bottom: 15px;
            font-size: 0.95rem;
        }}

        .insight-item b {{
            color: var(--accent-color);
            display: block;
            margin-bottom: 3px;
        }}

        /* Animations */
        @keyframes fadeInDown {{
            from {{ opacity: 0; transform: translateY(-20px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}

        @keyframes slideInLeft {{
            from {{ opacity: 0; transform: translateX(-30px); }}
            to {{ opacity: 1; transform: translateX(0); }}
        }}

        .mono {{ font-family: 'JetBrains Mono', monospace; }}

        .cve-list {{
            margin-top: 15px;
            padding: 15px;
            background: rgba(0,0,0,0.3);
            border-radius: 10px;
            display: none;
        }}

        .cve-item {{
            border-bottom: 1px solid rgba(255,255,255,0.05);
            padding: 10px 0;
        }}

        .cve-item:last-child {{ border: none; }}
        
        .cve-id {{ color: var(--risk-high); font-weight: 600; }}

    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Defensive Intelligence Dashboard</h1>
            <p class="subtitle">Real-time Bluetooth Security Posture Analysis</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <span class="stat-value">{total_devices}</span>
                <span class="stat-label">Devices Discovered</span>
            </div>
            <div class="stat-card">
                <span class="stat-value">{total_cves}</span>
                <span class="stat-label">Total Potential CVEs</span>
            </div>
            <div class="stat-card">
                <span class="stat-value">{high_risk_devices}</span>
                <span class="stat-label">High Risk Targets</span>
            </div>
        </div>

        <div class="main-layout">
            <div class="device-list">
    """

    for i, device in enumerate(sorted_reports):
        score = device.get("aggregate_risk_score", 0)
        risk_class = "risk-high" if score > 50 else ("risk-med" if score > 10 else "risk-low")
        badge_class = "badge-high" if score > 50 else ("badge-med" if score > 10 else "badge-low")
        risk_text = "Critical" if score > 50 else ("Medium" if score > 10 else "Low")
        
        cves = device.get("vulnerabilities", [])
        
        html_content += f"""
                <div class="device-card {risk_class}">
                    <div class="device-header">
                        <span class="device-name">{device['device']['name']}</span>
                        <span class="risk-badge {badge_class}">{risk_text} Risk</span>
                    </div>
                    <div class="device-details">
                        <div><span class="stat-label">MAC Address</span><br><span class="mono">{device['device']['address']}</span></div>
                        <div><span class="stat-label">Signal Strength</span><br><span class="mono">{device['device']['rssi']} dBm</span></div>
                        <div><span class="stat-label">Risk Score</span><br><span class="mono">{score}</span></div>
                        <div><span class="stat-label">Services Found</span><br><span class="mono">{len(device['services_detected'])}</span></div>
                    </div>
                    
                    <button class="vulnerability-toggle" onclick="toggleCVEs({i})">View {len(cves)} Vulnerabilities</button>
                    
                    <div id="cve-{i}" class="cve-list">
        """
        
        # Limit display to first 5 for performance/readability
        for cve in cves[:5]:
            html_content += f"""
                        <div class="cve-item">
                            <span class="cve-id">{cve['id']}</span>
                            <p style="font-size: 0.85rem; margin-top: 5px;">{cve['description'][:150]}...</p>
                        </div>
            """
        
        if len(cves) > 5:
            html_content += f"<p style='text-align:center; padding-top:10px; font-size:0.8rem; color:var(--text-secondary)'>+ {len(cves) - 5} more detected</p>"

        html_content += """
                    </div>
                </div>
        """

    html_content += """
            </div>

            <div class="insights-sidebar">
                <div class="insight-box">
                    <h3>🛡️ Defensive Spotlight</h3>
                    <div class="insight-item">
                        <b>Proximity Attack Vector</b>
                        Devices with RSSI > -50 dBm are physically close enough for highly reliable packet injection.
                    </div>
                    <div class="insight-item">
                        <b>Shadow Bluetooth Discovery</b>
                        Unknown devices with "Unknown" names often represent unauthorized hardware or IoT devices with factory-default configurations.
                    </div>
                </div>

                <div class="insight-box">
                    <h3>💡 Mitigation Steps</h3>
                    <div class="insight-item">
                        <b>Update Firmware</b>
                        Prioritize devices with "Critical" risk scores. They contain architectural flaws like BlueBorne.
                    </div>
                    <div class="insight-item">
                        <b>Disable HID Services</b>
                        If a device exposes HID (Human Interface Device) services unnecessarily, it can be spoofed as a keyboard.
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        function toggleCVEs(id) {
            const el = document.getElementById('cve-' + id);
            el.style.display = el.style.display === 'block' ? 'none' : 'block';
        }
    </script>
</body>
</html>
    """

    with open(DASHBOARD_FILE, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[✓] Defensive Dashboard generated: {DASHBOARD_FILE}")

if __name__ == "__main__":
    generate_dashboard()
