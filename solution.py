import click
import socket
import requests

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
        return None

@click.command()
@click.option('--ip', help='The IP address to check.')
@click.option('--domain', '-d', help='The domain name to check.')
@click.option('--filename', '-f', type=click.Path(exists=True), help='File containing IP addresses to check.')
def main(ip, domain, filename):
    ips = set()
    lines = []
    if filename:
        with open(filename, 'r') as file:
            lines = file.readlines()
        lines = [line.strip() for line in lines]
        for line in lines:
            if line:
                if line.replace('.', '').isdigit():
                    ips.add(line)
                else:
                    resolved_ip = resolve_domain_to_ip(line)
                    if resolved_ip:
                        ips.add(resolved_ip)

    elif domain:
        resolved_ip = resolve_domain_to_ip(domain)
        if resolved_ip:
            ips.add(resolved_ip)
    elif ip:
        ips.add(ip)

    for ip in ips:
        if ip:
            print(f"Checking IP: {ip}")
            check_ip(ip)
            print('-' * 60)

if __name__ == '__main__':
    main()

