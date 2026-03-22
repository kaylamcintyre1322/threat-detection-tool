Threat Detection Tool

Overview

This project is a Python-based threat intelligence tool that analyzes SHA-256 file hashes by cross-referencing them against VirusTotal and MalwareBaazar. It identifies malicious files and extracts key indicators of compromise such as detection scores, malware families, and detection engine results. This tool generates a structured report that supports further analysis. 

Features 
- Retrieves detection scores 
- identifies the name and type of malware family 
- tags descriptive labels 
- extract detection engine results and lists which antiviues engines flagged it
- generates threat intelligence reports 


Tools and Environment 
- Python
- VirusTotal API
- MalwareBazaar API
- Linux

Quick Start
#clone the repostiory:
git clone https://github.com/kaylamcintyre13222/threat-detection-tool.git
cd threat-detection-tool

#Set your API key for VirusTotal and MalwareBazaar:
export VT_API_Key= "your_api_key_here"
export MB_API_Key= "your_malwarebazaar_api_key"

#Install dependencies:
pip install -r requirements.txt


#Run the script:
python3 hash_lookup.py 


Example output
   return {
       "source": "VirusTotal",
       "sha256": "34eee77a6b289da54a212c7429494a62080c566f5fd7e6662b6ab0d9158f5d81"
       "detection_score": "38/70"
       "malware_family":Mirai".
       "tags": [
          "elf"
          "Mirai"
       ]
       "first_seen": "2026-03-16T21:41:13Z",
       "detection_engines": [
       {"engine": "Lionic",
        "result": "Trojan.Linux.Mirau.1"
       },
       {
        "engine": "MicroWorld-eScan",
        "Result": "Trojan.Linux.Mirai.1"
       },
       {
        "engine": "ClamAV"
        "result": "Unix.Trojan.Mirai-10017641-0"
       }


Use case

This tool can be used to analyze suspicious files and to identify malware threats. 

Author

Kayla McIntyre (The "Outside" Specialist)
