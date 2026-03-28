# Threat Detection Tool

## Overview

Python-based threat intelligence tool that analyzes SHA-256 file hashes by cross-referencing them against VirusTotal and MalwareBaazar. It identifies malicious files and extracts key indicators of compromise (IOC's) such as detection scores, malware families, and antivirus engine results. This tool generates a structured report that supports further security analysis. 

## Features

Generates a threat intelligence report that:
- Retrieves detection score (e.g., 36/70)
- Identifies the name and type of Malware family (e.g., Mirai)
- tags descriptive labels
- lists antivirus engines that flagged the file

## How it works 

- User inputs a SHA-256 file hash
- The tool queries VirusTotal for detection statistics and MalwareBaazar for malware family and associated tags
- Keys indicators of compromise (IOC's) are extracted from the results
- A structued JSON report is genereated to support further analysis

## Tools and Environment

- Python
- VirusTotal API
- MalwareBazaar API
- Linux

## Quick Start

### 1. Clone the repostiory:

```bash
git clone https://github.com/kaylamcintyre13222/threat-detection-tool.git
cd threat-detection-tool
```

### 2. Create a virtual environment (recommended)
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Obtain API Keys from VirusTotal and MalwareBaazar

This tool uses API keys from VirusTotal and MalwareBazaar to generate results. You must create an account with both platforms to generate your own API keys.

click the links below to generate your API keys:
- VirusTotal: https://www.virustotal.com/
- MalwareBazaar: https://bazaar.abuse.ch/

### 4. Set up API Keys

#### Create a .env file:

```
nano .env 
```

#### Add your API keys to file:

```env
VT_API_KEY=enter_your_virustotal_api_key
MB_API_KEY=enter_your_malwarebazaar_api_key
```
#### Save the file

- Ctrl O + Enter + Ctrl X

### 5. Install dependencies

```
pip install -r requirements.txt
```

### 6. Run tool

```
python3 hash_lookup.py 
```
## Example output

```json
      {
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
```

 ## Use Case

 This tool can be used to:
 - Analyze suspicious file hashes to determine if they are malicious
 - identify malware families associated with known threats
 - extract indicators of compromise (IOC's) for threat detection and monitoring
 - Asisist security analysts in threat investigations and incident response

## Author

Kayla McIntyre 
