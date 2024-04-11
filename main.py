import pandas as pd
import requests

# API key and IP addresses to be analyzed
api_key = "07059b0ecdba0cd18b2fde38553243c2d725bb156b43516ba0de70d0a515c183"
ip_addresses = ['192.169.69.25', '118.213.179.177', '8.8.8.8', '110.87.251.7', '42.7.5.213', '4.56.78z.98', '234567654', 'sdfghjiuytr', '1.1.1.1']

# URL for VirusTotal API and headers containing API key
url = "https://www.virustotal.com/api/v3/ip_addresses/"
headers = {
    'x-apikey': api_key,
}

res = []  # Initialize the result list outside the loop

# Iterate through each IP address for analysis
for ip in ip_addresses:
    response = requests.get(f"{url}{ip}", headers=headers)

    # Check if the request was successful
    if response.status_code == 200:
        data = response.json()
        attributes = data.get('data', {}).get('attributes', {})
        country = attributes.get('country', 'N/A')
        last_analysis_results = attributes.get('last_analysis_results', {})
        as_owner = data['data']['attributes']['as_owner']
        
        # Counting different analysis result categories
        malicious_count = attributes.get('last_analysis_stats', {}).get('malicious', 0)
        suspicious_count = attributes.get('last_analysis_stats', {}).get('suspicious', 0)
        undetected_count = attributes.get('last_analysis_stats', {}).get('undetected', 0)
        harmless_count = attributes.get('last_analysis_stats', {}).get('harmless', 0)

        # Calculate risk assessment based on analysis results
        positives = data.get('positives', 0)
        malicious_category = any(cat in data.get('category', []) for cat in ['malware', 'phishing'])
        risk_assessment = 'low'
        if malicious_count > 3 or malicious_category:
            risk_assessment = 'high'
        elif malicious_count >= 1 or positives > 0:
            risk_assessment = 'medium'

        # Append the analysis results to the result list
        res.append({
            'IP': ip,
            'Country': country,
            'Last Analysis Results': last_analysis_results,
            'Owner': as_owner,
            'Malicious Category': any(result.get('result') == 'malicious' for result in last_analysis_results.values()),
            'malicious_Count': malicious_count,
            'suspicious_Count': suspicious_count,
            'undetected_Count': undetected_count,
            'harmless_Count': harmless_count,
            'Risk Assessment': risk_assessment
        })
    else:
        # If the request was not successful, add a placeholder entry to the result list
        res.append({
            'IP': ip,
            'Country': 'Invalid IP',
            'Last Analysis Results': {},
            'Owner': 'N/A',
            'Malicious Category': False,
            'malicious_Count': 0,
            'suspicious_Count': 0,
            'undetected_Count': 0,
            'harmless_Count': 0,
            'Risk Assessment': 'N/A'
        })

# Convert the result list to a pandas DataFrame and save it to an Excel file
df = pd.DataFrame(res)
df.to_excel('vtapi_multi_ips.xlsx', index=False)
print('Result saved to vtapi_multi_ips.xlsx')
