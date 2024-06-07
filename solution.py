import click
import requests
import csv
import os
from datetime import datetime
import ipaddress

from constants import API_KEY


def report_for_ip(ip, page_num):
    url = f'https://api.abuseipdb.com/api/v2/reports'
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90',
        'perPage': '25',
        'page': str(page_num)
    }
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }

    last_page = 1

    response = requests.get(url, headers=headers, params=params)
    data = response.json()

    if response.status_code == 200 and 'data' in data:
        last_page = data['data'].get('lastPage', 0)
        reports = data['data']['results']
        print(f"Reports for IP Address: {ip}")
        for report in reports:
            print(f"Reported At: {report['reportedAt']}")
            print(f"Comment: {report['comment']}")
            print(f"Categories: {report['categories']}")
            print(f"Reporter ID: {report['reporterId']}")
            print(f"Reporter Country: {report['reporterCountryCode']}")
            print('-' * 40)
    else:
        print(f"Error fetching reports for IP {ip}: {data.get('errors', [{}])[0].get('detail', 'Unknown error')}")
    if page_num != last_page:
        page_num +=1
        if page_num < 3:
            report_for_ip(ip, page_num)
        else:
            print(f"We stopped at {page_num}, but {last_page} is the last page")


def check_ip(ip):
    url = f'https://api.abuseipdb.com/api/v2/check'
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }

    response = requests.get(url, headers=headers, params=params)
    data = response.json()
    if response.status_code == 200:
        is_white_listed = data['data'].get('isWhitelisted', False)
        number_of_reports = data['data']['totalReports']
        print(f"IP Address: {data['data']['ipAddress']}")
        print(f"Is White Listed: {is_white_listed if is_white_listed else 'N/A'}")
        print(f"Last Reported At: {data['data'].get('lastReportedAt', 'N/A')}")
        print(f"Abuse Confidence Score: {data['data']['abuseConfidenceScore']}")
        print(f"Total Reports: {number_of_reports}")

        if not is_white_listed and number_of_reports > 0:
            report_for_ip(ip=ip, page_num=1)
            # print("Recent Reports:")
            #for report in data['data']['reports']:
            #    print(f" - {report['reportedAt']}: {report['comment']}")
        else:
            print("No recent reports found.")

        # Additional information
        print(f"ISP: {data['data'].get('isp', 'N/A')}")
        print(f"Usage Type: {data['data'].get('usageType', 'N/A')}")
        print(f"Domain Name: {data['data'].get('domain', 'N/A')}")
        print(f"Country: {data['data'].get('countryName', 'N/A')}")
        print(f"City: {data['data'].get('city', 'N/A')}")
    else:
        print(f"Error: {data['errors'][0]['detail']}")

def resolve_domain_to_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        print(f"Error: Unable to resolve domain {domain}")

def is_valid_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def read_ips_from_file(filename, ip_set):
    with open(filename, 'r') as file:
        for line in file:
            line = line.strip()
            if line:
                ip_set.add(line if is_valid_ip(line) else resolve_domain_to_ip(line))

def add_ip(ip_set, ip=None, domain=None):
    if ip and is_valid_ip(ip):
        ip_set.add(ip)
    if domain:
        resolved_ip = resolve_domain_to_ip(domain)
        if resolved_ip and is_valid_ip(resolved_ip):
            ip_set.add(resolved_ip)

def save_blacklist_to_csv(blacklist_data, blacklist_dir):
    now = datetime.now()
    filename = f"{now.year}-{now.month:02d}-{now.day:02d} {now.hour:02d}:{now.minute:02d}.csv"
    filepath = os.path.join(blacklist_dir, filename)

    os.makedirs(blacklist_dir, exist_ok=True)

    with open(filepath, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['ipAddress', 'abuseConfidenceScore'])
        for entry in blacklist_data:
            writer.writerow([entry['ipAddress'], entry['abuseConfidenceScore']])

    return filepath

def download_blacklist(blacklist_dir, confidence_minimum=75):
    url = 'https://api.abuseipdb.com/api/v2/blacklist'
    headers = {
        'Key': API_KEY,
        'Accept': 'application/json'
    }
    params = {
        'confidenceMinimum': confidence_minimum
    }

    # default limit is 10,000 IPs with no subscription
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        blacklist_data = response.json()['data']
        filepath = save_blacklist_to_csv(blacklist_data, blacklist_dir)
        return filepath
    else:
        response.raise_for_status()

@click.command()
@click.option('--ip', '-i', help='The IP address to check.')
@click.option('--domain', '-d', help='The domain name to check.')
@click.option('--filename', '-f', type=click.Path(exists=True), help='File containing IP addresses to check.')
@click.option('--blacklist', is_flag=True, help='Download blacklist from AbuseIPDB.')
def main(ip, domain, filename, blacklist):
    ips = set()

    if blacklist:
        blacklist_dir = "blacklist"

        filepath = download_blacklist(blacklist_dir)
        click.echo(f'Blacklist saved to: {filepath}')

    if filename:
        read_ips_from_file(filename, ips)
    else:
        add_ip(ips, ip, domain)

    for ip in ips:
        if ip:
            print(f"Checking IP: {ip}")
            check_ip(ip)
            print('-' * 60)

if __name__ == '__main__':
    main()

