import os
import json
import time
import requests
import ipaddress
import urllib.parse
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth


load_dotenv()


USERNAME = os.getenv("HETZNER_USERNAME")
PASSWORD = os.getenv("HETZNER_PASSWORD")
SERVER_IDS = [s.strip() for s in os.getenv("SERVER_IDS", "").split(",") if s.strip()]
GITHUB_META_URL = "https://api.github.com/meta"
ROBOT_API_BASE = "https://robot-ws.your-server.de"
CACHE_FILE = "cached_github_ips.json"
CHECK_INTERVAL_SECONDS = 3600  # 1 hour


def get_github_ipv4s():
    """Fetch GitHub webhook IPv4 addresses."""
    print("[*] Fetching GitHub hook IPv4 addresses...")
    r = requests.get(GITHUB_META_URL)
    r.raise_for_status()
    data = r.json()
    hook_ips = data.get("hooks", [])
    return sorted([ip for ip in hook_ips if ipaddress.ip_network(ip).version == 4])


def load_cached_ips():
    if not os.path.exists(CACHE_FILE):
        return []
    try:
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []


def save_cached_ips(ips):
    with open(CACHE_FILE, "w") as f:
        json.dump(ips, f)


def fetch_current_rules(server_id):
    print(f"[*] Fetching current firewall config for server {server_id}...")
    url = f"{ROBOT_API_BASE}/firewall/{server_id}"
    r = requests.get(url, auth=HTTPBasicAuth(USERNAME, PASSWORD))
    if r.status_code != 200:
        print(f"[!] Failed to fetch current rules: {r.status_code}")
        return [], []
    data = r.json()
    input_rules = data.get("firewall", {}).get("rules", {}).get("input", [])
    output_rules = data.get("firewall", {}).get("rules", {}).get("output", [])
    return input_rules, output_rules


def build_firewall_payload(existing_input, existing_output, github_ips):
    print("[*] Merging GitHub rules with existing firewall config...")

    payload = {
        "status": "active",
        "whitelist_hos": "true"
    }

    # Remove old GitHub rules
    merged_input = [rule for rule in existing_input if not rule.get("name", "").startswith("github_")]

    # Add updated GitHub IP rules
    for ip in github_ips:
        merged_input.append({
            "name": f"github_{ip.replace('/', '_')}",
            "ip_version": "ipv4",
            "src_ip": ip,
            "dst_port": "",
            "action": "accept"
        })

    # Input rules
    for idx, rule in enumerate(merged_input):
        base = f"rules[input][{idx}]"
        for k, v in rule.items():
            if v is not None:
                payload[f"{base}[{k}]"] = str(v)

    # Output rules (unchanged)
    for idx, rule in enumerate(existing_output):
        base = f"rules[output][{idx}]"
        for k, v in rule.items():
            if v is not None:
                payload[f"{base}[{k}]"] = str(v)

    return payload


def apply_firewall(server_id, payload):
    print(f"[*] Applying firewall to server {server_id}...")

    url = f"{ROBOT_API_BASE}/firewall/{server_id}"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    encoded_body = urllib.parse.urlencode(payload, quote_via=urllib.parse.quote_plus)

    response = requests.post(
        url,
        auth=HTTPBasicAuth(USERNAME, PASSWORD),
        data=encoded_body,
        headers=headers
    )

    if response.status_code in [200, 201, 202]:
        print(f"[✓] Firewall accepted for server {server_id} (status {response.status_code})")
    else:
        print(f"[!] Failed for server {server_id}: {response.status_code} - {response.text}")


def sync_firewalls():
    github_ips = get_github_ipv4s()
    print(f"[✓] Got {len(github_ips)} GitHub hook IPv4 ranges")

    cached_ips = load_cached_ips()

    if github_ips == cached_ips:
        print("[✓] IPs unchanged — skipping update.")
        return

    print("[!] GitHub IPs changed — updating firewalls...")
    save_cached_ips(github_ips)

    for server_id in SERVER_IDS:
        existing_input, existing_output = fetch_current_rules(server_id)
        payload = build_firewall_payload(existing_input, existing_output, github_ips)
        apply_firewall(server_id, payload)


def main():
    while True:
        print("\n=== GitHub → Hetzner Firewall Sync ===")
        try:
            sync_firewalls()
        except Exception as e:
            print(f"[!] Exception: {e}")
        print(f"[*] Sleeping for {CHECK_INTERVAL_SECONDS // 60} minutes...\n")
        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
