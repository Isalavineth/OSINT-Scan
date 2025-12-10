import asyncio
import aiohttp
import argparse
import socket
import sys
import os

class Color:
    RED = "\033[31m"
    RED_BRIGHT = "\033[91m"
    GREEN = "\033[32m"
    GREEN_BRIGHT = "\033[92m"
    YELLOW = "\033[33m"
    YELLOW_BRIGHT = "\033[93m"
    BLUE = "\033[34m"
    BLUE_BRIGHT = "\033[94m"
    MAGENTA = "\033[35m"
    MAGENTA_BRIGHT = "\033[95m"
    CYAN = "\033[36m"
    CYAN_BRIGHT = "\033[96m"
    WHITE = "\033[97m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

async def is_ip(target):
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        return False

async def geo_lookup(ip):
    url = f"https://ipwho.is/{ip}?fields=continent,continent_code,country,country_code,region,region_code,city,latitude,longitude,postal,calling_code,capital,borders"
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            data = await resp.json()

            output = [
            f"{Color.CYAN_BRIGHT}{Color.BOLD}:: Geo Lookup for {ip}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Continent:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['continent']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Continent code:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['continent_code']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Country:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['country']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Country code:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['country_code']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Region:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['region']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Region code:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['region_code']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}City:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['city']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Latitude:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['latitude']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Longitude:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['longitude']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Postal code:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['postal']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Calling code:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['calling_code']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Capital:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['capital']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Borders:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['borders']}\n{Color.RESET}",
            ""]

        return "\n".join(output)

async def whois_lookup(ip):
    url = f"https://ipwho.is/{ip}?fields=ip,type,continent,country,region,connection,timezone"
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            data = await resp.json()
            output = [
            f"{Color.CYAN_BRIGHT}{Color.BOLD}:: WHOIS Lookup for {ip}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}IP:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['ip']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Type:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['type']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Continent:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['continent']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Country:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['country']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Region:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['region']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Org:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['connection']['org']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}ISP:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['connection']['isp']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Domain:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['connection']['domain']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}ID:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['timezone']['id']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Timezone:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['timezone']['abbr']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}UTC:{Color.RESET} {Color.WHITE}{Color.BOLD}{data["timezone"]["utc"]}{Color.RESET}\n",
            ""]

        return "\n".join(output)

async def connection_lookup(ip):
    url = f"https://ipwho.is/{ip}?fields=connection"
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            data = await resp.json()
            output = [
            f"{Color.CYAN_BRIGHT}{Color.BOLD}:: Connection lookup for {ip}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}ASN:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['connection']['asn']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Org:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['connection']['org']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}ISP:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['connection']['isp']}\n{Color.RESET}",
            ""]

        return "\n".join(output)

async def abuseipdb_lookup(ip):
    api_key = os.getenv("ABUSEIPDB_KEY")
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }

    async with aiohttp.ClientSession() as session:
        async with session.get(url=url, headers=headers, params=querystring) as resp:
            data = await resp.json()
            output = [
            f"{Color.CYAN_BRIGHT}{Color.BOLD}:: AbuseIPDB lookup for {ip}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Is public:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['data']['isPublic']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}IP version:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['data']['ipVersion']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Is whitelisted:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['data']['isWhitelisted']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Abuse confidence score:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['data']['abuseConfidenceScore']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Country Code:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['data']['countryCode']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Usage Type:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['data']['usageType']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}ISP:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['data']['isp']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Domain:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['data']['domain']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Hostnames:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['data']['hostnames']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Is Tor:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['data']['isTor']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Total reports:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['data']['totalReports']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Number of distinct users:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['data']['numDistinctUsers']}{Color.RESET}",
            f"{Color.YELLOW_BRIGHT}Last Report:{Color.RESET} {Color.WHITE}{Color.BOLD}{data['data']['lastReportedAt']}\n{Color.RESET}",
            ""]

        return "\n".join(output)


async def dns_lookup(domain):
    if not domain:
        return f"{Color.RED}:: DNS Lookup skipped (Target is an IP with no resolvable domain){Color.RESET}"
    async with aiohttp.ClientSession() as session:
        async with session.get(f"https://networkcalc.com/api/dns/lookup/{domain}") as resp:
            data = await resp.json()
            if 'records' not in data:
                return f"{Color.RED}:: No DNS records found for {domain}{Color.RESET}"
            output = [f"{Color.CYAN_BRIGHT}{Color.BOLD}:: DNS Lookup for domain {domain}{Color.RESET}"]
            for record_type, record_values in data['records'].items():
                if record_values:
                    output.append(f"{Color.YELLOW_BRIGHT}{record_type}{Color.RESET}")
                for values in record_values:
                    output.append(f"{Color.WHITE}{Color.BOLD}{str(values)}{Color.RESET}")
                output.append("\n")

            return "\n".join(output)

common_ports = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 162, 389, 443, 445, 514, 515, 530, 548, 554, 587, 631, 636,
    873, 902, 912, 993, 995, 1025, 1080, 1194, 1433, 1434, 1521, 1723,
    1883, 2049, 2083, 2087, 2089, 2222, 2375, 2376, 2483, 2484, 25565,
    2601, 2604, 3000, 3074, 3128, 3306, 3389, 3478, 3690, 3724, 4444,
    4567, 5000, 5060, 5080, 5201, 5222, 5432, 5601, 5672, 5900, 5984,
    6379, 6443, 6667, 6881, 7001, 7002, 7070, 7233, 7777, 8000, 8008,
    8080, 8081, 8123, 8181, 8443, 8531, 8888, 9000, 9090, 9200, 9300,
    9418, 10000, 11211, 27017, 27018, 27019]

async def scan_port(ip, port, timeout=1):

    sem = asyncio.Semaphore(200)
    async with sem:
        try:
            connection = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(connection, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return port
        except:
            return None

async def scan_common_port(ip):
    tasks = [scan_port(ip, port) for port in common_ports]
    open_ports = []
    for coro in asyncio.as_completed(tasks):
        result = await coro
        if result:
            open_ports.append(result)

    output = [f"{Color.CYAN_BRIGHT}{Color.BOLD}:: Port Scan for {ip}{Color.RESET}"]
    for port in open_ports:
        output.append(f"{Color.GREEN_BRIGHT}[+]Port {port}/TCP OPEN{Color.RESET}")

    output.append("\n")
    output.append(f"{Color.YELLOW_BRIGHT}open ports:{Color.RESET} {Color.WHITE}{Color.BOLD}{open_ports}{Color.RESET}")
    return "\n".join(output)

ascii_banner = rf"""{Color.RED_BRIGHT}{Color.BOLD}
   ____  _____ _____   ________   _____                
  / __ \/ ___//  _/ | / /_  __/  / ___/_________ _____ 
 / / / /\__ \ / //  |/ / / /     \__ \/ ___/ __ `/ __ \
/ /_/ /___/ // // /|  / / /     ___/ / /__/ /_/ / / / /
\____//____/___/_/ |_/ /_/     /____/\___/\__,_/_/ /_/ {Color.RESET}

        {Color.RED}{Color.BOLD}OSINTScan — Network Reconnaissance Toolkit{Color.RESET}

{Color.BLUE_BRIGHT}OSINT Scan is a fast, async-powered reconnaissance tool for gathering intelligence on IPs and domains using DNS, WHOIS, geolocation, AbuseIPDB, and common port scanning.{Color.RESET}
"""

async def main():
    parser = argparse.ArgumentParser(description=ascii_banner, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("target", nargs='?', help="Target IP or Domain")
    parser.add_argument("-g", "--geo", action="store_true", help=f"Retrieve geolocation information about the target IP (country, region, city, coordinates, etc.)")
    parser.add_argument("-w", "--whois", action="store_true", help="Fetch WHOIS-style IP ownership details (ISP, organization, location, timezone)")
    parser.add_argument("-d", "--dns", action="store_true", help="Perform DNS enumeration on the target domain (A, MX, NS, TXT, and other DNS records)")
    parser.add_argument("-p", "--port", action="store_true", help="Scan the target host for the most commonly used ports and detect which ones are open\nDisclaimer: Lightweight common-port scan only. Firewalls and filtering may hide or distort results.")
    parser.add_argument("-s", "--abuseIPDB", action="store_true", help="Query AbuseIPDB for blacklist reports, reputation score, and abuse history for the target IP")
    parser.add_argument("-a", "--all", action="store_true",help="Run all available recon modules at once (geo, whois, DNS, port scan, connection data, AbuseIPDB)")
    args = parser.parse_args()

    if not args.target:
        print(ascii_banner)
        print(f"{Color.GREEN}Usage: python3 test.py <target> [flags]{Color.GREEN}")
        print(f"{Color.GREEN}Try: python3 test.py -h{Color.GREEN}")
        sys.exit(1)

    if not (args.geo or args.whois or args.dns or args.port or args.abuseIPDB or args.all):
        print(f"{Color.YELLOW}:: No flags provided. Running Basic Scan (Geo, DNS, WHOIS)...{Color.RESET}\n")
        args.geo = True
        args.whois = True
        args.dns = True

    user_input = args.target

    if await is_ip(user_input):
        print(f"{Color.GREEN}Scanning {user_input}{Color.RESET}\n")
        target_ip = user_input

        try:
            target_domain = socket.gethostbyaddr(target_ip)[0]
            print(f"{Color.GREEN}Reverse DNS: Resolved {target_ip} to {target_domain}{Color.RESET}\n")
        except:
            target_domain = None
    else:
        target_domain = user_input
        try:
            target_ip = socket.gethostbyname(target_domain)
            print(f"{Color.GREEN}Resolved {target_domain} to {target_ip}{Color.RESET}\n")
        except:
            print(f"{Color.RED}Invalid Domain.{Color.RESET}")
            sys.exit(1)

    if args.all:
        results = await asyncio.gather(whois_lookup(target_ip), dns_lookup(target_domain), geo_lookup(target_ip), connection_lookup(target_ip), abuseipdb_lookup(target_ip), scan_common_port(target_ip))
        print("\n".join(results))

    if args.geo:
        print(await geo_lookup(target_ip))

    if args.whois:
        print(await whois_lookup(target_ip))

    if args.dns:
        print(await dns_lookup(target_domain))

    if args.abuseIPDB:
        print(await abuseipdb_lookup(target_ip))

    if args.port:
        print(await scan_common_port(target_ip))


if __name__ == "__main__":
    asyncio.run(main())