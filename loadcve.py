import requests
import sqlite3
import time
from datetime import datetime

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DB_FILE = "bluetooth_cves.db"

RESULTS_PER_PAGE = 2000
RATE_DELAY = 6  # free tier safety


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS cves (
        id TEXT PRIMARY KEY,
        description TEXT,
        published TEXT,
        last_modified TEXT,
        cvss REAL
    )
    """)

    cur.execute("CREATE INDEX IF NOT EXISTS idx_cvss ON cves(cvss)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_published ON cves(published)")

    conn.commit()
    return conn


def extract_cvss(cve):
    try:
        metrics = cve["cve"]["metrics"]
        if "cvssMetricV31" in metrics:
            return metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        if "cvssMetricV30" in metrics:
            return metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
    except Exception:
        pass
    return None


def save_to_db(conn, vulnerabilities):
    cur = conn.cursor()

    for item in vulnerabilities:
        cve = item["cve"]
        cve_id = cve["id"]

        description = ""
        if cve.get("descriptions"):
            description = cve["descriptions"][0]["value"]

        published = cve.get("published")
        last_modified = cve.get("lastModified")
        cvss = extract_cvss(item)

        cur.execute("""
        INSERT OR IGNORE INTO cves
        (id, description, published, last_modified, cvss)
        VALUES (?, ?, ?, ?, ?)
        """, (cve_id, description, published, last_modified, cvss))

    conn.commit()


def fetch_bluetooth_cves():
    start_index = 0
    conn = init_db()

    while True:
        params = {
            "keywordSearch": "bluetooth",
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": start_index
        }

        print(f"[*] Fetching page {start_index}")

        response = requests.get(BASE_URL, params=params)

        if response.status_code == 429:
            print("[!] Rate limited. Sleeping 30 seconds...")
            time.sleep(30)
            continue

        response.raise_for_status()
        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break

        save_to_db(conn, vulnerabilities)

        total = data.get("totalResults", 0)
        start_index += RESULTS_PER_PAGE

        print(f"[+] Stored page. Progress: {start_index}/{total}")

        if start_index >= total:
            break

        time.sleep(RATE_DELAY)

    conn.close()
    print("[✓] Bluetooth CVEs stored in SQLite successfully.")


if __name__ == "__main__":
    fetch_bluetooth_cves()