# VirusTotal-IP-Analyzer
It is a Python tool that utilizes the VirusTotal API to analyze IP addresses, providing detailed insights into their reputation and potential security risks. It generates comprehensive reports including country, owner, analysis results, and risk assessment.

## Introduction

The VirusTotal IP Analyzer is a Python tool designed to leverage the VirusTotal API for analyzing IP addresses and generating comprehensive reports regarding their reputation and potential security risks. This tool provides valuable insights into the geographical location, owner details, analysis results, and risk assessment of the specified IP addresses.

## Features

- **API Integration**: Utilizes the VirusTotal API to fetch detailed information about IP addresses.
- **Geolocation Data**: Retrieves geographical location information such as country for each IP address.
- **Owner Identification**: Identifies the owner or organization associated with each IP address.
- **Analysis Results**: Provides a breakdown of analysis results including malicious, suspicious, undetected, and harmless counts.
- **Risk Assessment**: Automatically calculates the risk assessment based on analysis results and categorization.

## Requirements

- Python 3.x
- VirusTotal API key (Get yours at https://www.virustotal.com/)
- Requests library (`pip install requests`)
- Pandas library (`pip install pandas`)

## Getting Started

1. Clone the repository or download the project files.
2. Obtain a VirusTotal API key from the official VirusTotal website.
3. Update the `api_key` variable in the script with your API key.
4. Install the required libraries using `pip install -r requirements.txt`.
5. Run the `vt_ip_analyzer.py` script and provide the list of IP addresses to analyze.

## Usage

```bash
python vt_ip_analyzer.py
```

Follow the on-screen instructions to enter the IP addresses you want to analyze. The tool will fetch data from the VirusTotal API and generate a detailed report in Excel format (`vtapi_multi_ips.xlsx`).


## Acknowledgments

- Thanks to the VirusTotal team for providing access to their powerful API.
- Special thanks to the open-source community for valuable contributions and feedback.

---
