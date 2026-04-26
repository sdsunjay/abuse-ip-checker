# solution.py
import csv
import os
import socket
import ipaddress
from datetime import datetime

import click

from abuse_ip_checker.config.config import get_api_key, get_all_keys, save_config, load_config, CONFIG_FILE, migrate_from_constants
from abuse_ip_checker.clients.sources import check_all_sources, fetch_abuseipdb_blacklist
from abuse_ip_checker.utils.output import format_table, format_verbose, format_json
from abuse_ip_checker.services.littlesnitch import load_littlesnitch_file, resolve_domain, is_public_ip


def is_valid_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def resolve_domain_to_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        click.echo(f"Warning: Unable to resolve domain {domain}", err=True)
        return None


def read_ips_from_file(filename):
    """Read IPs and domains from a file, return set of IPs."""
    ips = set()
    with open(filename, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if is_valid_ip(line):
                ips.add(line)
            else:
                resolved = resolve_domain_to_ip(line)
                if resolved:
                    ips.add(resolved)
    return ips


def collect_ips(ip=None, domain=None, filename=None):
    """Collect IPs from all input sources."""
    ips = set()
    if filename:
        ips.update(read_ips_from_file(filename))
    if ip and is_valid_ip(ip):
        ips.add(ip)
    if domain:
        resolved = resolve_domain_to_ip(domain)
        if resolved:
            ips.add(resolved)
    return ips


def display_results(results, output_json, verbose):
    """Display results in the requested format."""
    if output_json:
        click.echo(format_json(results))
    elif verbose:
        click.echo(format_verbose(results))
    else:
        click.echo(format_table(results))


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """Multi-source threat intelligence IP checker."""
    migrate_from_constants()
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command()
@click.option("--ip", "-i", help="IP address to check.")
@click.option("--domain", "-d", help="Domain name to check.")
@click.option("--filename", "-f", type=click.Path(exists=True), help="File containing IPs/domains to check.")
@click.option("--json", "output_json", is_flag=True, help="Output results as JSON.")
@click.option("--verbose", "-v", is_flag=True, help="Show full details for each IP.")
def check(ip, domain, filename, output_json, verbose):
    """Check IPs/domains against all configured threat intel sources."""
    ips = collect_ips(ip, domain, filename)
    if not ips:
        raise click.ClickException("No valid IPs to check. Use --ip, --domain, or --filename.")

    click.echo(f"Checking {len(ips)} IPs against all configured sources...\n", err=True)

    results = []
    for addr in sorted(ips):
        result = check_all_sources(addr)
        results.append(result)

    display_results(results, output_json, verbose)


@cli.command("scan-littlesnitch")
@click.argument("filepath", type=click.Path(exists=True))
@click.option("--json", "output_json", is_flag=True, help="Output results as JSON.")
@click.option("--verbose", "-v", is_flag=True, help="Show full details for each IP.")
def scan_littlesnitch(filepath, output_json, verbose):
    """Parse a Little Snitch export and check all allowed public IPs."""
    click.echo(f"Parsing Little Snitch export: {filepath}\n", err=True)

    entries = load_littlesnitch_file(filepath)
    click.echo(f"Found {len(entries)} unique targets in allow rules.", err=True)

    # Separate IPs and domains, resolve domains
    ips_with_context = {}  # ip -> list of processes

    for entry in entries:
        ip = entry.get("ip")
        domain = entry.get("domain")
        processes = entry.get("processes", [])

        if ip:
            ips_with_context.setdefault(ip, []).extend(processes)
        elif domain:
            resolved = resolve_domain(domain)
            if resolved and is_public_ip(resolved):
                ips_with_context.setdefault(resolved, []).extend(processes)

    # Deduplicate process lists
    for ip in ips_with_context:
        ips_with_context[ip] = sorted(set(ips_with_context[ip]))

    click.echo(f"Checking {len(ips_with_context)} public IPs...\n", err=True)

    results = []
    for addr in sorted(ips_with_context.keys()):
        result = check_all_sources(addr)
        result.associated_processes = ips_with_context[addr]
        results.append(result)

    display_results(results, output_json, verbose)


@cli.command()
def blacklist():
    """Download the AbuseIPDB blacklist to CSV."""
    api_key = get_api_key("abuseipdb")
    if not api_key:
        raise click.ClickException(
            "AbuseIPDB API key not configured. Run 'abuse-ip-checker configure' first."
        )

    click.echo("Downloading blacklist from AbuseIPDB...", err=True)
    blacklist_data = fetch_abuseipdb_blacklist(api_key)
    if blacklist_data is None:
        raise click.ClickException("Failed to download blacklist (see warnings above).")

    blacklist_dir = "blacklist"
    os.makedirs(blacklist_dir, exist_ok=True)
    now = datetime.now()
    filename = f"{now.year}-{now.month:02d}-{now.day:02d} {now.hour:02d}:{now.minute:02d}.csv"
    filepath = os.path.join(blacklist_dir, filename)

    with open(filepath, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ipAddress", "abuseConfidenceScore"])
        for entry in blacklist_data:
            writer.writerow([entry["ipAddress"], entry["abuseConfidenceScore"]])

    click.echo(f"Blacklist saved to: {filepath} ({len(blacklist_data)} IPs)")


@cli.command()
def configure():
    """Interactively configure API keys."""
    config = load_config()
    if "api_keys" not in config:
        config["api_keys"] = {}

    sources = {
        "abuseipdb": "AbuseIPDB (https://www.abuseipdb.com/account/api)",
        "virustotal": "VirusTotal (https://www.virustotal.com/gui/my-apikey)",
        "shodan": "Shodan (https://account.shodan.io/)",
    }

    click.echo("Configure API keys for threat intelligence sources.\n")
    click.echo("Leave blank to skip. Keys are saved to ~/.abuse-ip-checker/config.yaml\n")

    for source, description in sources.items():
        current = config["api_keys"].get(source)
        if current:
            masked = current[:8] + "..." + current[-4:]
            prompt = f"{description}\n  Current: {masked}\n  New key (blank to keep)"
        else:
            prompt = f"{description}\n  Key (blank to skip)"

        new_key = click.prompt(prompt, default="", show_default=False)
        if new_key:
            config["api_keys"][source] = new_key
            click.echo("  Saved.\n")
        elif current:
            click.echo("  Kept existing.\n")
        else:
            click.echo("  Skipped.\n")

    save_config(config)
    click.echo(f"Configuration saved to {CONFIG_FILE}")

    # Show summary
    click.echo("\nConfigured sources:")
    all_keys = get_all_keys()
    for source in sources:
        status = "configured" if all_keys.get(source) else "not set"
        click.echo(f"  {source}: {status}")
    click.echo("\nFree sources (always active): DNS Blocklists, WHOIS, ipinfo.io")


def main():
    cli()


if __name__ == "__main__":
    main()
