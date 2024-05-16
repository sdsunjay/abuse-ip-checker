# Abuse IP Checker

This script checks IP addresses or domain names against the AbuseIPDB API to retrieve information about potential abuse reports. The script can take a single IP address, a single domain name, or a file containing multiple IP addresses or domain names.

## Prerequistes
Create an account and request  an API key on the [AbuseIPDB website](https://www.abuseipdb.com/). It is free if you have under 1000 requests per month.

## Requirements

- Python 3.x
- `click` library
- `requests` library

## Installation

1. Clone the repository or download the script.
1. Install the required Python libraries using pip:
   ```bash
   $ pip install requests click
   ```
1. Replace `YOUR_API_KEY` with your actual AbuseIPDB API key in the script.

## Usage

### Command Line Options

- `--ip`: Specifies a single IP address to check.
- `--domain` or `-d`: Specifies a single domain name to check.
- `--filename` or `-f`: Specifies a file containing IP addresses or domain names to check. Each IP address or domain name should be on a new line.

### Examples

#### Check a Single IP Address

To check a single IP address:

```bash
$ python solution.py --ip 142.250.217.0
```

#### Check a Single Domain Name

To check a single domain name:

```bash
$ python solution.py --domain example.com
```

#### Check IP Addresses or Domain Names from a File

To check IP addresses or domain names from a file:

```bash
$ python solution.py --filename ips_or_domains.txt
```

### File Format

The file specified with the `--filename` option should contain one IP address or domain name per line, for example:

```plaintext
142.250.217.0
example.com
192.168.1.1
anotherdomain.com
```

### Output

The script outputs the following information for each IP address checked:

- IP Address
- Abuse Confidence Score
- Total Reports
- Recent Reports (if available)
- ISP
- Usage Type
- Domain Name
- Country
- City

### Error Handling

If the script encounters an error (e.g., unable to resolve a domain name or issues with the AbuseIPDB API), it will print an appropriate error message.

### Example Output

```bash
$ python solution.py --ip 142.250.217.0
```
```yaml
Checking IP: 142.250.217.0
IP Address: 142.250.217.0
Abuse Confidence Score: 0
Total Reports: 0
No recent reports found.
ISP: Google LLC
Usage Type: Data Center/Web Hosting/Transit
Domain Name: google.com
Country: United States
City: Mountain View
------------------------------------------------------------
```

```bash
$ python solution.py --ip 192.142.226.153
```
```yaml
Checking IP: 192.142.226.153
IP Address: 192.142.226.153
Is White Listed: N/A
Last Reported At: 2024-04-22T16:35:57+00:00
Abuse Confidence Score: 57
Total Reports: 79
Reports for IP Address: 192.142.226.153
Reported At: 2024-04-22T16:35:57+00:00
Comment: Credential brute-force attacks on webpage logins
Categories: [18]
Reporter ID: 144976
Reporter Country: DE
----------------------------------------
Reported At: 2024-04-20T14:02:16+00:00
Comment: Multiple WP scan detected from same source ip.-111
Categories: [18]
Reporter ID: 102992
Reporter Country: ID
----------------------------------------
Reported At: 2024-04-12T03:49:56+00:00
Comment: Events: TCP SYN Discovery or Flooding, Seen 4 times in the last 10800 seconds
Categories: [4]
Reporter ID: 131395
Reporter Country: BR
----------------------------------------
Reported At: 2024-04-02T08:11:09+00:00
Comment: GET /vendor/
Categories: [21]
Reporter ID: 60763
Reporter Country: FR
----------------------------------------
Reported At: 2024-03-29T12:45:26+00:00
Comment: (cpanel) Failed cPanel login from 192.142.226.153 (TH/Thailand/-): 1 in the last 3600 secs
Categories: [18, 21]
Reporter ID: 55388
Reporter Country: MY
----------------------------------------
Reported At: 2024-03-27T09:07:00+00:00
Comment: Unauthorized login attempts [ pure-ftpd-constant, sshd, pure-ftpd]
Categories: [5, 18, 22]
Reporter ID: 31143
Reporter Country: ES
```

## License

This project is licensed under the MIT License.
"""
