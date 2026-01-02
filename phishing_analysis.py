import argparse
from email.parser import BytesParser
from email.parser import HeaderParser
from email import policy
import json
import requests
import re
import os
import sys

RESET  = "\033[0m"
GREEN  = "\033[92m"

headers = { 
    "from",
    "to",
    "subject",
    "date",
    "reply-to",
    "return-path",
    "received",
    "authentication-results",
    "received-spf",
    "dkim-signature"
}
selected_headers = {}
emailParser = argparse.ArgumentParser(
    prog='PhishingAnalysis',
    description='Automated Header Analysis'
    )

emailParser.add_argument('filename', nargs='?')
emailParser.add_argument('--headers-stdin', action='store_true')
emailParser.add_argument("--headers-file")
args = emailParser.parse_args()
msg = None

if args.headers_stdin:
    raw = sys.stdin.read()
    if not raw.strip():
        raise SystemExit("No headers provided on stdin.")
    if not raw.endswith("\n\n"):
        raw = raw.strip() + "\n\n"
    msg = HeaderParser(policy=policy.default).parsestr(raw)

elif args.headers_file:
    with open(args.headers_file, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()
    if not raw.endswith("\n\n"):
        raw = raw.strip() + "\n\n"
    msg = HeaderParser(policy=policy.default).parsestr(raw)

elif args.filename:
    path = args.filename
    if not path.lower().endswith(".eml"):
        raise SystemExit("Enter a valid email format '.eml' file")
    with open(path, "rb") as eml:
        msg = BytesParser(policy=policy.default).parse(eml)

else:
    raise SystemExit("Provide a .eml filename OR use --headers-stdin OR --headers-file")

for k, v in msg.items():
    key = k.lower()
    if key in headers:
        selected_headers[key] = v

print(f"\n{GREEN}Full Report of the Phishing Email:\n" )
auth_result = selected_headers['authentication-results']
spf_status = re.search(r"spf=(pass|fail|neutral)", auth_result)
dkim_status = re.search(r"dkim=(pass|fail)", auth_result)
if dkim_status and spf_status:
    print(f"AUTH: \n {spf_status.group().upper()}")
    print(f" {dkim_status.group().upper()}\n")

headers_ip = {
    "received-spf",
    "received",
    "authentication-results"
}
ips = []
for h in headers_ip:
    value = selected_headers.get(h, "")
    match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', value) # extrai ip dos varios fields
    if match:
        ips.append(match.group())
if ips and len(set(ips)) == 1:
    clean_ip = ips[0]   
else:
    print("IPs inválidos ou inconsistentes")

def check_ip_vt(ip:str) -> None:
    """Contacts the VirusTotal API and searches to security vendors flags on the IP

    Args:
        ip (str): IP Address 
    """
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        print("VARIAVEL NÃO DEFINIDA (VT_API_KEY)")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
                "accept": "application/json",
                "x-apikey": api_key,
               }

    response = requests.get(url, headers=headers)
    response_json = response.json()
    stats = response_json["data"]["attributes"]["last_analysis_stats"]
    malicious = stats.get("malicious", 0)
    harmless = stats.get("harmless", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected

    print(f'The IP Address \"{ip}\" as score of {malicious}/{total} in VirusTotal\n')

check_ip_vt(clean_ip)

domain_headers = ["from", "reply-to", "return-path"]
domains = []

for h in domain_headers:
    value = selected_headers.get(h, "")
    # extrai domínios do header (pode ter mais de um)
    matches = re.findall(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', value)
    domains.extend(matches)

def check_domain_vt(domain:str) -> None:
    """Contacts the VirusTotal API and searches to security vendors flags on the Domain

    Args:
        domain (str): Domain Addresses present in the SMTP header of the email 
    """
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        print("VARIAVEL NÃO DEFINIDA (VT_API_KEY)")
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    headers = {
                "accept": "application/json",
                "x-apikey": api_key,
               }

    response = requests.get(url, headers=headers)
    response_json = response.json()
    stats = response_json["data"]["attributes"]["last_analysis_stats"]
    malicious = stats.get("malicious", 0)
    harmless = stats.get("harmless", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected

    print(f'The Domain Address \"{domain}\" as score of {malicious}/{total} in VirusTotal\n')

domain_headers = ["from", "reply-to", "return-path"]
domains = []

for h in domain_headers:
    value = selected_headers.get(h, "")
    # extrai domínios do header (pode ter mais de um)
    matches = re.findall(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', value)
    for domain in matches:
        domains.append((h, domain))

for header, domain in domains:
    print(f"[{header.upper()}] Domain found: {domain}")
    check_domain_vt(domain)  

def check_ip_abuse(ip:str) -> None:
    """Contacts the AbuseIPDB API and access the Confidence of Abuse score of the IP

    Args:
        ip (str): IP Address
    """
    api_key= os.getenv("ABUSE_API_KEY")
    if not api_key:
        print("VARIABLE NOT DEFINED (ABUSE_API_KEY)")
    
    url = f'https://api.abuseipdb.com/api/v2/check'

    querystring = {
    'ipAddress': ip,
    'maxAgeInDays': '90'
    }
    headers = {
    'Accept': 'application/json',
    'Key': api_key,
    }
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    response_json = json.loads(response.text)
    stats = response_json['data']
    abuseScore = stats.get('abuseConfidenceScore', 0)
    print(f'The IP Address \"{ip}\" as {abuseScore}% Confidence of Abuse in AbuseIPDB\n')

check_ip_abuse(clean_ip)
