# --------------------------------------------
# VirusTotal API Lookup Tool
#
# A command-line tool for investigating the reputation of IP addresses, 
# URLs, file hashes (MD5, SHA-1, SHA-256), and domains using the VirusTotal v3 API.
#
# Author: Jonathan Stallard
# Version: 1.3
# Last Revised: 7/29/2025
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
        return datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S UTC')
    except:
        return "Unknown"

def interpret_risk(malicious, suspicious):
    if malicious >= 10:
        return "HIGH"
    elif malicious > 0 or suspicious > 3:
        return "MEDIUM"
    else:
        return "LOW"

def print_stats(stats):
    return (
        f"  Harmless   : {stats.get('harmless', 0)} engines\n"
        f"  Suspicious : {stats.get('suspicious', 0)} engines\n"
        f"  Malicious  : {stats.get('malicious', 0)} engines\n"
        f"  Undetected : {stats.get('undetected', 0)} engines\n"
    )

def check_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        r.raise_for_status()
        data = r.json()["data"]["attributes"]

        output_lines = [
            f"IP Report for: {ip}",
            "-" * 50,
            f"{'Country:':15} {data.get('country', 'Unknown')}",
            f"{'ASN:':15} {data.get('asn', 'N/A')} ({data.get('as_owner', 'N/A')})",
            f"{'Reputation:':15} {data.get('reputation', 'N/A')}",
            "",
            "Scan Stats:",
            print_stats(data.get('last_analysis_stats', {})).rstrip(),
            f"Risk Level: {interpret_risk(data['last_analysis_stats'].get('malicious', 0), data['last_analysis_stats'].get('suspicious', 0))}",
        ]

        resolutions = data.get('resolutions', [])
        if resolutions:
            output_lines.append("\nRecent DNS Resolutions:")
            for r in resolutions[:5]:
                output_lines.append(f"  - {r.get('hostname')} -> {r.get('ip_address', 'N/A')} (Last Resolved: {format_time(r.get('date', 0))})")

        detected_urls = data.get('detected_urls', [])
        if detected_urls:
            output_lines.append("\nDetected Malicious URLs:")
            for u in detected_urls[:5]:
                output_lines.append(f"  - {u.get('url', '')} (Positives: {u.get('positives', 0)})")

        output_lines.append(f"\n{'Network:':15} {data.get('network', 'N/A')}")
        whois = data.get('whois', 'N/A').strip()
        output_lines.append("\nWHOIS Information:")
        output_lines.append("-" * 17)
        output_lines.append(whois)
        output_lines.append("-" * 50)

        return "\n".join(output_lines)
    except Exception as e:
        return f"Error: {e}"

def check_url(url):
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    vt_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
    try:
        r = requests.get(vt_url, headers=HEADERS, timeout=10)
        r.raise_for_status()
        data = r.json()["data"]["attributes"]

        output_lines = [
            f"URL Report for: {url}",
            "-" * 50,
            f"{'Reputation:':15} {data.get('reputation', 'N/A')}",
            f"{'Categories:':15} {', '.join(data.get('categories', {}).values()) or 'None'}",
            f"{'Tags:':15} {', '.join(data.get('tags', [])) or 'None'}",
            f"{'First Seen:':15} {format_time(data.get('first_submission_date', 0))}",
            f"{'Last Scanned:':15} {format_time(data.get('last_analysis_date', 0))}",
            "",
            "Scan Stats:",
            print_stats(data.get('last_analysis_stats', {})).rstrip(),
            f"Risk Level: {interpret_risk(data['last_analysis_stats'].get('malicious', 0), data['last_analysis_stats'].get('suspicious', 0))}",
        ]

        return "\n".join(output_lines)
    except Exception as e:
        return f"Error: {e}"

def check_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        r.raise_for_status()
        data = r.json()["data"]["attributes"]

        creation_ts = data.get('creation_date')
        if isinstance(creation_ts, int):
            creation_date_str = format_time(creation_ts)
        else:
            creation_date_str = creation_ts or 'N/A'

        whois = data.get('whois', 'N/A').strip()

        output_lines = [
            f"Domain Report for: {domain}",
            "-" * 50,
            f"{'Registrar:':15} {data.get('registrar', 'N/A')}",
            f"{'Creation Date:':15} {creation_date_str}",
            f"{'Reputation:':15} {data.get('reputation', 'N/A')}",
            f"{'Categories:':15} {', '.join(data.get('categories', {}).values()) or 'None'}",
            "",
            "Scan Stats:",
            print_stats(data.get('last_analysis_stats', {})).rstrip(),
            f"Risk Level: {interpret_risk(data['last_analysis_stats'].get('malicious', 0), data['last_analysis_stats'].get('suspicious', 0))}",
            "",
            "WHOIS Information:",
            "-" * 17,
            whois,
            "-" * 50
        ]

        return "\n".join(output_lines)
    except Exception as e:
        return f"Error: {e}"

def check_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 404:
            return "File hash not found."
        r.raise_for_status()
        data = r.json()["data"]["attributes"]

        classification = data.get('popular_threat_classification', {}).get('suggested_threat_label', 'N/A')

        output_lines = [
            f"VirusTotal Hash Report for: {file_hash}",
            "-" * 50,
            f"{'File Name:':15} {data.get('meaningful_name', 'Unknown')}",
            f"{'File Type:':15} {data.get('type_tag', 'N/A')}",
            f"{'Reputation:':15} {data.get('reputation', 'N/A')}",
            f"{'Threat Family:':15} {classification}",
            f"{'First Seen:':15} {format_time(data.get('first_submission_date', 0))}",
            f"{'Last Scanned:':15} {format_time(data.get('last_analysis_date', 0))}",
            "",
            "Scan Stats:",
            print_stats(data.get('last_analysis_stats', {})).rstrip(),
            f"Risk Level: {interpret_risk(data['last_analysis_stats'].get('malicious', 0), data['last_analysis_stats'].get('suspicious', 0))}",
        ]

        return "\n".join(output_lines)
    except Exception as e:
        return f"Error: {e}"

def main():
    print("VirusTotal Investigator CLI")
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
