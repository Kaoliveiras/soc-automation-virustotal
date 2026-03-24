import os
import requests
from dotenv import load_dotenv
from pathlib import Path

# Setup path and load environment variables
base_path = Path(__file__).resolve().parent
env_path = base_path / '.env'
load_dotenv(dotenv_path=env_path)

VT_API_KEY = os.getenv("VT_API_KEY")


def get_ip_reputation(ip_address):
    """Queries VirusTotal API v3 for IP reputation data."""
    if not VT_API_KEY:
        print(f"[!] Critical Error: API Key not found at {env_path}")
        return

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json()[
                'data']['attributes']['last_analysis_stats']
            print(f"\n[+] SOC ANALYSIS REPORT: {ip_address}")
            print(f"    - Malicious: {stats['malicious']}")
            print(f"    - Harmless: {stats['harmless']}")
        else:
            print(f"[!] API Error: Status Code {response.status_code}")
    except Exception as e:
        print(f"[!] Connection Error: {e}")


if __name__ == "__main__":
    print("--- 🛡️ SOC AUTOMATION: VirusTotal Scanner ---")
    target_ip = input("Enter IP for analysis: ").strip()
    if target_ip:
        get_ip_reputation(target_ip)
