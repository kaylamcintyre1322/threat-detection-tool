# Threat Detection Tool

## Overview

This project is a Python-based threat intelligence tool that analyzes SHA-256 file hashes by cross-referencing them against VirusTotal and MalwareBaazar. It identifies malicious files and extracts key indicators of compromise such as detection scores, malware families, and detection engine results. This tool generates a structured report that supports further analysis. 

## Features 
Generates a structure threat intelligence report that:
- Retrieves detection score (e.g., 36/70)
- Identifies the name and type of Malware

## Tools and Environment 
- Python
- VirusTotal API
- MalwareBazaar API
- Linux

## Quick Start
### Clone the repostiory:
git clone https://github.com/kaylamcintyre13222/threat-detection-tool.git
cd threat-detection-tool

### Retrieve API Keys from VirusTotal and MalwareBaazar
This tool uses API keys from VirusTotal and MalwareBazaar to generate results. You must create an account with VirusTotal and MalwareBazaar and generate your own API keys. 

### Set up API Keys
Create a .env file:
nano .env 

Add your API keys to file
VT_API_KEY=enter_your_virustotal_api_key
MB_API_KEY=enter_your_malwarebazaar_api_key

Save the file
- Ctrl O + Enter + Ctrl X

### Install dependencies
pip install -r requirements.txt


### Run tool
python3 hash_lookup.py 

## Example output
```json   
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
 

Author

Kayla McIntyre (The "Outside" Specialist)
