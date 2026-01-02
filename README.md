# Phishing Analysis Tool
This tool analyzes email headers to detect phishing attempts and provides scores for authentication (SPF/DKIM), IP/domain reputation, and more.

## Setup:
1. **Create a Virtual Environment (venv):**
   - To keep your environment isolated and clean.
2. **Create two Environment Variables:**
   - `VT_API_KEY` (for VirusTotal API)
   - `ABUSE_API_KEY` (for AbuseIPDB API)
   - To use these services, you'll need to sign up for free API keys on their respective websites:
     - [VirusTotal](https://www.virustotal.com)
     - [AbuseIPDB](https://www.abuseipdb.com)
3. **Install the required packages:**
   - Run the following command to install the necessary packages:
     ```bash
     pip install requests
     ```
## Usage:
This tool can be run with one of the following options:

1. **Analyze a .eml file:**
   ```bash
   python3 phishing_analysis.py {filename.eml}
   ```

2. **Analyze headers from stdin (copy-paste email headers):**
   ```bash
   python3 phishing_analysis.py --headers-stdin
   ```
   After running this command, paste the email headers and press **Ctrl + D** to finish input.

3. **Analyze headers from a text file:**
   ```bash
   python3 phishing_analysis.py rawmsg.txt
   ```
## Output
The tool will generate a full report with the following details:
- **SPF and DKIM status**: Shows whether the email passed SPF and DKIM authentication.
- **IP Address score**: Displays the security vendor scores for the email's originating IP from VirusTotal.
- **IP Address Confidence score**: Provides the AbuseIPDB confidence score, which indicates the likelihood of the IP being used for malicious activity.
- **Domain analysis**: Scores for every domain found in the email's headers, indicating their reputation.

The report will be displayed in the terminal/console.

## Coming Soon
- **URL Analysis**: Ability to check URLs found within the email for malicious content using VirusTotal.
- **More advanced threat detection features**: New ways to analyze and identify phishing attempts.

