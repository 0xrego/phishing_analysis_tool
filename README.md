# Phishing Analysis Tool

## Setup:
    - Create a Virtual Environment (venv)
    - Create two Environment Variables: (VT_API_KEY, ABUSE_API_KEY) in order to use this tool u need to create an api key which is free in VirusTotal and AbuseIPDB.
    - Install "requests" package with the command:
        - pip install requests

## Usage:

### It depends in what you have for analysis, at the moment you have 3 options:

        - python3 phishing_analysis.py {filename.eml}
        - python3 phishing_analysis.py --headers-stdin 
            In this particular case after u put the argument u can copy-paste the headers of an Outlook email file and then **PRESS Ctrl + D** 
        - python3 phishing_analysis.py rawmsg.txt
## Output 

### A full report of a phishing email with:
    - SPF and DKIM
    - IP Address score of all security vendors in VirusTotal.
    - IP Address Confidence of Abuse score in AbuseIPDB.
    - A score for every domain present in the headers.

## Comming Soon

### URL Analysis

### Other Features
