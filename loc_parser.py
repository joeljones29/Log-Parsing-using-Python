#can get details on the ip address of the intruder if possible 
import re
import pandas as pd
import requests

log_pattern = re.compile(r'(^\S+).*Failed password for (?:invalid user )?(\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
parsed_data = []

with open('auth.log', 'r') as log_file:
    for line in log_file:
        match = log_pattern.search(line)
        if match:
            parsed_data.append({
                'timestamp': match.group(1),
                'user': match.group(2),
                'ip_address': match.group(3)
            })

if not parsed_data:
    print("No 'Failed password' events found in the log file.")
else:
    df = pd.DataFrame(parsed_data)

    
    print("\n--- Performing IP Geolocation (this may take a moment) ---")
    unique_ips = df['ip_address'].unique()
    geo_data = []

    for ip in unique_ips:
        try:
            
            response = requests.get(f'http://ip-api.com/json/{ip}').json()
            if response['status'] == 'success':
                geo_data.append({
                    'ip_address': ip,
                    'country': response.get('country', 'N/A'),
                    'city': response.get('city', 'N/A'),
                    'isp': response.get('isp', 'N/A')
                })
        except requests.exceptions.RequestException as e:
            print(f"Could not connect for IP {ip}: {e}")

    geo_df = pd.DataFrame(geo_data)

    ip_counts = df['ip_address'].value_counts().reset_index()
    ip_counts.columns = ['ip_address', 'attack_count']

    
    final_report = pd.merge(ip_counts, geo_df, on='ip_address', how='left')

    print("\n--- Final Attacker Report ---")
    print(final_report)