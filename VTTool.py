# --------------------------------------------
# VirusTotal API Lookup Tool
#
# A command-line tool for investigating the reputation of IP addresses, 
# URLs, file hashes (MD5, SHA-1, SHA-256), and domains using the VirusTotal v3 API.
#
# Author: Jonathan Stallard
# Version: 1.0
# Last Revised: 7/2/2025
# --------------------------------------------
# Requires a free or premium VirusTotal API key.
# API Keys are loaded securely from a `.env` file.
# --------------------------------------------

import requests
import os
import base64
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

HEADERS = {
    "x-apikey": VT_API_KEY
}

def format_time(ts):
    try:
        return datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return "Unknown"

def interpret_risk(malicious, suspicious):
    if malicious >= 10:
        return "⚠️ Risk Level: HIGH"
    elif malicious > 0 or suspicious > 3:
        return "⚠️ Risk Level: MEDIUM"
    else:
        return "✅ Risk Level: LOW"

def print_stats(stats):
    return (
        f"  ✅ Harmless     : {stats.get('harmless', 0)} engines\n"
        f"  ⚠️ Suspicious   : {stats.get('suspicious', 0)} engines\n"
        f"  ❌ Malicious    : {stats.get('malicious', 0)} engines\n"
        f"  🤷 Undetected   : {stats.get('undetected', 0)} engines\n"
    )

def check_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        r.raise_for_status()
        data = r.json()["data"]["attributes"]

        output = f"\n📡 IP Report for: {ip}\n" + "-"*40 + "\n"
        output += f"Country       : {data.get('country', 'Unknown')}\n"
        output += f"ASN           : {data.get('asn', 'N/A')} ({data.get('as_owner', 'N/A')})\n"
        output += f"Reputation    : {data.get('reputation', 'N/A')}\n"
        output += print_stats(data.get('last_analysis_stats', {}))
        output += interpret_risk(data['last_analysis_stats'].get("malicious", 0), data['last_analysis_stats'].get("suspicious", 0))
        return output
    except Exception as e:
        return f"❌ Error: {e}"

def check_url(url):
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    vt_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
    try:
        r = requests.get(vt_url, headers=HEADERS, timeout=10)
        r.raise_for_status()
        data = r.json()["data"]["attributes"]

        output = f"\n🌐 URL Report for: {url}\n" + "-"*40 + "\n"
        output += f"Reputation    : {data.get('reputation', 'N/A')}\n"
        output += f"Categories    : {', '.join(data.get('categories', {}).values()) or 'None'}\n"
        output += f"Tags          : {', '.join(data.get('tags', [])) or 'None'}\n"
        output += f"First Seen    : {format_time(data.get('first_submission_date', 0))}\n"
        output += f"Last Scanned  : {format_time(data.get('last_analysis_date', 0))}\n"
        output += print_stats(data.get('last_analysis_stats', {}))
        output += interpret_risk(data['last_analysis_stats'].get("malicious", 0), data['last_analysis_stats'].get("suspicious", 0))
        return output
    except Exception as e:
        return f"❌ Error: {e}"

def check_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        r.raise_for_status()
        data = r.json()["data"]["attributes"]

        output = f"\n🌐 Domain Report for: {domain}\n" + "-"*40 + "\n"
        output += f"Registrar     : {data.get('registrar', 'N/A')}\n"
        output += f"Creation Date : {data.get('creation_date', 'N/A')}\n"
        output += f"Reputation    : {data.get('reputation', 'N/A')}\n"
        output += f"Categories    : {', '.join(data.get('categories', {}).values()) or 'None'}\n"
        output += print_stats(data.get('last_analysis_stats', {}))
        output += interpret_risk(data['last_analysis_stats'].get("malicious", 0), data['last_analysis_stats'].get("suspicious", 0))
        return output
    except Exception as e:
        return f"❌ Error: {e}"

def check_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 404:
            return "❌ File hash not found."
        r.raise_for_status()
        data = r.json()["data"]["attributes"]

        output = f"\n🧬 File Hash Report for: {file_hash}\n" + "-"*40 + "\n"
        output += f"File Name     : {data.get('meaningful_name', 'Unknown')}\n"
        output += f"File Type     : {data.get('type_tag', 'N/A')}\n"
        output += f"Reputation    : {data.get('reputation', 'N/A')}\n"
        output += f"First Seen    : {format_time(data.get('first_submission_date', 0))}\n"
        output += f"Last Scanned  : {format_time(data.get('last_analysis_date', 0))}\n"
        output += print_stats(data.get('last_analysis_stats', {}))
        output += interpret_risk(data['last_analysis_stats'].get("malicious", 0), data['last_analysis_stats'].get("suspicious", 0))
        return output
    except Exception as e:
        return f"❌ Error: {e}"

def main():
    print("🧪 VirusTotal Investigator CLI")
    print("Type 'exit' at any time to quit.\n")

    while True:
        print("\nSelect what you want to check:")
        print("1. IP address")
        print("2. URL")
        print("3. File hash (MD5, SHA-1, SHA-256)")
        print("4. Domain")
        choice = input("\nEnter choice (1-4): ").strip()

        if choice.lower() == "exit":
            break

        if choice not in {"1", "2", "3", "4"}:
            print("Invalid choice. Try again.")
            continue

        query = input("Enter the value: ").strip()
        if query.lower() == "exit":
            break

        if choice == "1":
            print(check_ip(query))
        elif choice == "2":
            print(check_url(query))
        elif choice == "3":
            print(check_hash(query))
        elif choice == "4":
            print(check_domain(query))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting.")
