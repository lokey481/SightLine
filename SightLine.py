import requests
import yaml
import dns.resolver
import socket
import builtwith
from urllib.parse import urlparse

# Load the configuration from the YAML file
with open('config.yaml', 'r') as config_file:
    config = yaml.safe_load(config_file)


def format_url(target_url):
    if not target_url.startswith(('http://', 'https://')):
        return 'http://' + target_url
    return target_url

def write_to_file(data):
    with open("Recon_Results.txt", "a") as f:
        f.write(data + "\n\n")

def use_builtwith(target_url):
    results = builtwith.parse(target_url)
    data = "BuiltWith Results:\n" + str(results)
    print(data)
    write_to_file(data)

def generate_subdomains(target_domain, wordlist_file):
    discovered_subdomains = set()

    with open(wordlist_file, 'r') as file:
        wordlist = [line.strip() for line in file.readlines()]

    for word in wordlist:
        subdomain = f"{word}.{target_domain}"
        if is_valid_subdomain(subdomain):
            discovered_subdomains.add(subdomain)
            write_to_file(subdomain)  # Write immediately

    return discovered_subdomains


def is_valid_subdomain(subdomain):
    try:
        result = dns.resolver.resolve(subdomain)
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False
    except dns.exception.Timeout:
        print(f"Timeout for {subdomain}")
        return False

def use_urlscan(target_url):
    API_KEY = config['urlscan']['api_key']
    headers = {
        "API-Key": API_KEY,
        "Content-Type": "application/json"
    }
    data = {
        "url": target_url
    }
    response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data)
    if response.status_code == 200:
        results = "URLScan Results:\n" + str(response.json())
        print(results)
        write_to_file(results)
    else:
        error_msg = "[!] URLScan request failed."
        print(error_msg)
        write_to_file(error_msg)




def use_security_trails(target_url):
    API_KEY = config['security_trails']['api_key']
    headers = {
        "apikey": API_KEY
    }
    domain = target_url.split("://")[-1].split("/")[0]
    response = requests.get(f"https://api.securitytrails.com/v1/domain/{domain}", headers=headers)
    if response.status_code == 200:
        results = "SecurityTrails Results:\n" + str(response.json())
        print(results)
        write_to_file(results)
    else:
        error_msg = f"[!] SecurityTrails request failed with status code {response.status_code}.\nResponse: {response.text}"
        print(error_msg)
        write_to_file(error_msg)

def dns_lookup(domain):
    records = ["A", "AAAA", "MX", "NS", "CNAME", "TXT"]
    for record in records:
        try:
            result = dns.resolver.resolve(domain, record)
            data = f"\n{record} Records for {domain}:\n"
            for val in result:
                data += str(val) + "\n"
            print(data)
            write_to_file(data)
        except:
            print(f"[!] No {record} records found for {domain}")
            write_to_file(f"[!] No {record} records found for {domain}")

def port_scan(domain):
    common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 3306, 3389, 8080]
    open_ports = []
    for port in common_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = s.connect_ex((domain, port))
        if result == 0:
            open_ports.append(port)
        s.close()

    if open_ports:
        data = f"\nOpen Ports on {domain}:\n" + ", ".join(str(port) for port in open_ports)
        print(data)
        write_to_file(data)
    else:
        print(f"No common ports open on {domain}")
        write_to_file(f"No common ports open on {domain}")

def main():
    target_url = input("Enter the target URL: ")
    target_url = format_url(target_url)
    domain = target_url.split("://")[-1].split("/")[0]

    with open("Recon_Results.txt", "w") as f:
        f.write(f"Recon results for {target_url}\n")
        f.write("=" * (len(target_url) + 20) + "\n\n")

    use_builtwith(target_url)
    use_urlscan(target_url)
    use_security_trails(target_url)
    dns_lookup(domain)
    port_scan(domain)
    
    
    wordlist_file = "subdomain_wordlist.txt"
    print("\nGenerated Subdomains:")
    for subdomain in generate_subdomains(domain, wordlist_file):
        print(subdomain)

def display_ascii_art():
    ascii_art = """



BBBBBBBBBBBBBBBBB###
####BGPYYY5PGB##B###
##BY??YYYYJYYYG####&
#B?7?YY55PPPYJ?P###&
##G##B##BBBBGPYJB##&
#####BP###BBGGPY5#&&
#####PYGBBGP55PP5B&&
####PYP5GPP5GGGGPG&&
###55GPBPGGBG5J5YJ5#
&&G5PGB#BBBGPGP5#BP5
&&#B#&#######&##&&#B
&&&&&&&&&#&&&&&&&&&&
 6MMMMb\ 68b          `MM               `MM'     68b                   
6M'    ` Y89           MM         /      MM      Y89                   
MM       ___   __      MM  __    /M      MM      ___ ___  __     ____  
YM.      `MM  6MMbMMM  MM 6MMb  /MMMMM   MM      `MM `MM 6MMb   6MMMMb 
 YMMMMb   MM 6M'`Mb    MMM9 `Mb  MM      MM       MM  MMM9 `Mb 6M'  `Mb
     `Mb  MM MM  MM    MM'   MM  MM      MM       MM  MM'   MM MM    MM
      MM  MM YM.,M9    MM    MM  MM      MM       MM  MM    MM MMMMMMMM
      MM  MM  YMM9     MM    MM  MM      MM       MM  MM    MM MM      
L    ,M9  MM (M        MM    MM  YM.  ,  MM    /  MM  MM    MM YM    d9
MYMMMM9  _MM_ YMMMMb. _MM_  _MM_  YMMM9 _MMMMMMM _MM__MM_  _MM_ YMMMM9 
             6M    Yb                                                  
             YM.   d9                                                  
              YMMMM9"""
    print(ascii_art)
    print("-N.A")

if __name__ == "__main__":
    display_ascii_art()
    main()