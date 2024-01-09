import requests
from bs4 import BeautifulSoup
import dns.resolver
import socket
from urllib.parse import urlparse
import re
import ssl
import subprocess
import platform
from ..general.errorresponse import error_response

class SSLCertificateInfo:
    def __init__(self, domain):
        self.domain = domain

    def get_html_content(self):
        """
        Retrieves the HTML content from the crt.sh website for the given domain.

        Returns:
        str: The HTML content of the crt.sh page corresponding to the queried domain.
        """
        url = f"https://crt.sh/?q={self.domain}"
        res = requests.get(url)
        return res.text

    def parse_html_content(self, html_content):
        """
        Parses the HTML content from the crt.sh website to extract certificate information.

        Args:
        html_content (str): HTML content as retrieved from the crt.sh website.

        Returns:
        list of dicts: A list where each dictionary contains information about one SSL certificate.
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        rows = soup.find_all('tr')[1:]  # Skipping the header row

        parsed_rows = []
        for row in rows:
            cols = row.find_all('td')
            if len(cols) < 7:  # Check if there are at least 7 columns
                # Log an error, skip the row, or fill in missing data with a placeholder
                return(f"No record found for {self.domain}")
                continue  # Skip this row and move to the next one

            # If the row has sufficient columns, parse it
            parsed_row = {
                'crt.sh ID': cols[0].text.strip(),
                'Logged At': cols[1].text.strip(),
                'Not Before': cols[2].text.strip(),
                'Not After': cols[3].text.strip(),
                'Common Name': cols[4].text.strip(),
                'Matching Identities': cols[5].text.strip(),
                'Issuer Name': cols[6].text.strip()
            }
            parsed_rows.append(parsed_row)

        return parsed_rows

    def get_certificate_info(self):
        """
        Retrieves and parses SSL certificate information for the domain.

        Returns:
        list of dicts: A list of dictionaries with parsed SSL certificate data.
        """
        html_content = self.get_html_content()
        return self.parse_html_content(html_content)

class dnsInfo:
    def __init__(self, domain):
        self.domain = domain
       
    def get_dns_info(self):
        """
        Retrieves DNS information for a specified hostname.

        Args:
        hostname (str): The hostname for which DNS information is requested. Can handle both raw hostnames and URLs.

        Returns:
        dict: A dictionary containing various DNS records (A, AAAA, MX, TXT, NS, CNAME, SOA, SRV, PTR) if successful,
            or an error message and a status code of 500 in case of failure.
        """
        hostname = self.domain
        # Handle URLs by extracting hostname
        if hostname.startswith('http://') or hostname.startswith('https://'):
            hostname = urlparse(hostname).hostname

        try:
            a = socket.gethostbyname(hostname)

            try: 
                aaaa = socket.getaddrinfo(hostname, None, socket.AF_INET6)[0][-1][0]
            except socket.gaierror:
                aaaa = []
            
            try:
                mx = [str(r.exchange) for r in dns.resolver.resolve(hostname, 'MX')]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                mx = []

            try:
                txt_records = dns.resolver.resolve(hostname, 'TXT')
                txt = [r.to_text() for r in txt_records]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                txt = []

            try:
                ns = [str(r.target) for r in dns.resolver.resolve(hostname, 'NS')]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                ns = []

            try:
                cname = [str(r.target) for r in dns.resolver.resolve(hostname, 'CNAME')]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                cname = []

            try:
                soa = dns.resolver.resolve(hostname, 'SOA')
                soa = [{"mname": str(record.mname), "rname": str(record.rname), "serial": record.serial, "refresh": record.refresh, "retry": record.retry, "expire": record.expire, "minimum": record.minimum} for record in soa]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                soa = []

            try:
                srv = [str(r.target) for r in dns.resolver.resolve(hostname, 'SRV')]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                srv = []

            try:
                ptr = [str(r.target) for r in dns.resolver.resolve(hostname, 'PTR')]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                ptr = []

            return {
                'statusCode': 200,
                'body': {
                    'A': a,
                    'AAAA': aaaa,
                    'MX': mx,
                    'TXT': txt,
                    'NS': ns,
                    'CNAME': cname,
                    'SOA': soa,
                    'SRV': srv,
                    'PTR': ptr
                }
            }
        except Exception as error:
            return {
                'statusCode': 500,
                'body': {
                    'error': str(error)
                }
            }

class hostsInfo:
    def __init__(self, domain):
        self.domain = domain

    def get_hosts_info(self):
        """
        Checks if the given URL is compatible with HSTS preload requirements.

        Args:
        url (str): The URL to check for HSTS preload compatibility.

        Returns:
        dict: A dictionary containing the status code, a message describing the HSTS compatibility,
            and additional details like whether the site is compatible, the HSTS header if present,
            and specific reasons for incompatibility if any.
        """

        def hsts_incompatible(message, status_code=200):
            return {
                'statusCode': status_code,
                'body': {'message': message, 'compatible': False},
            }

        url = self.domain
        if not url:
            return {
                'statusCode': 400,
                'body': {'error': 'URL parameter is missing!'},
            }

        try:
            response = requests.get(url)
        except requests.exceptions.RequestException as error:
            return error_response(f'Error making request: {error}')

        hsts_header = response.headers.get('strict-transport-security')

        if not hsts_header:
            return hsts_incompatible('Site does not serve any HSTS headers.')
        else:
            max_age_match = re.search(r'max-age=(\d+)', hsts_header)
            includes_sub_domains = 'includeSubDomains' in hsts_header
            preload = 'preload' in hsts_header

            if not max_age_match or int(max_age_match.group(1)) < 10886400:
                return hsts_incompatible('HSTS max-age is less than 10886400.')
            elif not includes_sub_domains:
                return hsts_incompatible('HSTS header does not include all subdomains.')
            elif not preload:
                return hsts_incompatible('HSTS header does not contain the preload directive.')
            else:
                return {
                    'statusCode': 200,
                    'body': {
                        'message': 'Site is compatible with the HSTS preload list!',
                        'compatible': True,
                        'hstsHeader': hsts_header,
                    },
                }

class letsEncryptInfo:
    def __init__(self, domain):
        self.domain = domain

    def check_lets_encrypt(self):
        """
        Checks if the domain associated with this instance is registered with Let's Encrypt.

        Returns:
        bool: True if the domain is registered with Let's Encrypt, False otherwise.
        """
        ctx = ssl.create_default_context()

        with ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as s:
            try:
                s.connect((self.domain, 443))
                cert = s.getpeercert()
                for issuer in cert.get('issuer', ()):
                    for key, value in issuer:
                        if key == 'organizationName' and 'Let\'s Encrypt' in value:
                            return True
                return False
            except Exception:
                return False

class PortsInfo:
    def __init__(self, domain):
        self.domain = domain

    # Commonly used ports.
    commonPorts = [
        20, 21, 22, 23, 25, 53, 80, 67, 68, 69,
        110, 119, 123, 143, 156, 161, 162, 179, 194,
        389, 443, 587, 993, 995,
        3000, 3306, 3389, 5060, 5900, 8000, 8080, 8888
    ]

    def get_ports_info(self):
        open_ports = []
        try:
            target = socket.gethostbyname(self.domain)
            for port in PortsInfo.commonPorts:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    socket.setdefaulttimeout(1)
                    result = s.connect_ex((target, port))
                    if result == 0:
                        open_ports.append(port)
        except socket.gaierror as error:
            return {'statusCode': 500, 'body': {'error': str(error)}}
        except socket.error as error:
            return {'statusCode': 500, 'body': {'error': str(error)}}
        except Exception as error:
            return {'statusCode': 500, 'body': {'error': str(error)}}

        return open_ports

class PingInfo:
    def __init__(self, domain):
        self.domain = domain

    def ping_domain(self):
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', self.domain]
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            return "ttl=" in output
        except subprocess.CalledProcessError:
            return False

class osInfo:
    def __init__(self, domain):
        self.domain = domain
    
    def ping_domain_ttl(self):
        """
        Checks if the specified host responds to a ping request and returns the TTL value and a base Nmap command.

        Args:
        host (str): The hostname or IP address to ping.

        Returns:
        tuple: A tuple containing the Nmap command, the TTL value if the host responds, and a boolean indicating 
            if the ping was successful. Returns None for TTL if the host does not respond or an error occurs.
        """
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', self.domain]
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            if "ttl=" in output:
                ttl = output.split('ttl=')[1].split(' ')[0]
                return ttl
            else:
                return None
        except subprocess.CalledProcessError:
            return None

    def get_os_info(self):
        """
        Retrieves the likely operating system of a host based on the TTL value.

        Args:
        ttl (str): The TTL (Time To Live) value as a string, typically obtained from a ping response.

        Returns:
        str: A string indicating the likely operating system of the host based on the TTL value, 
            or 'Unknown OS' if the TTL is not indicative of a common operating system.
        """
        ttl = self.ping_domain_ttl()
        if ttl is None:
            return "Unknown OS (No TTL)"

        try:
            ttl = int(ttl)
            if 64 <= ttl <= 128:
                return "Linux"
            elif 128 < ttl <= 255:
                return "Windows"
            elif ttl < 64:
                return "OpenBSD/Cisco/Oracle"
            else:
                return "Unknown OS"
        except ValueError:
            return "Unknown OS (Invalid TTL)"

class whoisInfo:
    def __init__(self, domain):
        self.domain = domain

    def whois(self):
        """
        Retrieves WHOIS information for a given domain.

        Args:
        domain (str): The domain name for which to retrieve WHOIS information.

        Returns:
        dict: A dictionary containing the status code and either the WHOIS information (if found) or an error message.
        """

        if not self.domain:
            return error_response('Missing domain parameter.')

        try:
            whois = subprocess.check_output(['whois', self.domain], universal_newlines=True)
            return {
                'statusCode': 200,
                'body': whois
            }
        except subprocess.CalledProcessError:
            return {
                'statusCode': 404,
                'body': {'error': 'WHOIS information not found'}
            }
        except Exception as error:
            return error_response(f'Error making request: {error}')

class dnsSecInfo:
    def __init__(self, domain):
        self.domain = domain

    def get_dnssec_info(self):
        """
        Retrieves DNSSEC information for a specified hostname.

        Args:
        hostname (str): The hostname for which DNSSEC information is requested. Can handle both raw hostnames and URLs.

        Returns:
        dict: A dictionary containing various DNSSEC records (DS, DNSKEY, NSEC, NSEC3, RRSIG) if successful,
            or an error message and a status code of 500 in case of failure.
        """
        dns_types = ['DNSKEY', 'DS', 'RRSIG']
        records = {}

        for dns_type in dns_types:
            url = f'https://dns.google/resolve?name={self.domain}&type={dns_type}'
            headers = {'Accept': 'application/dns-json'}

            try:
                response = requests.get(url, headers=headers)
                response.raise_for_status()
                dns_response = response.json()

                if 'Answer' in dns_response:
                    records[dns_type] = {'isFound': True, 'answer': dns_response['Answer'], 'response': dns_response['Answer']}
                else:
                    records[dns_type] = {'isFound': False, 'answer': None, 'response': dns_response}
            except requests.RequestException as error:
                raise Exception(f"Error fetching {dns_type} record: {error}")

        return records

class mxInfo:
    def __init__(self, domain):
        self.domain = domain

    def get_mx_info(self):
        """
        Retrieves MX information for a specified hostname.

        Args:
        hostname (str): The hostname for which MX information is requested. Can handle both raw hostnames and URLs.

        Returns:
        dict: A dictionary containing various MX records (MX, A, AAAA, CNAME) if successful,
            or an error message and a status code of 500 in case of failure.
        """
        try:
            mx_records = dns.resolver.resolve(self.domain, 'MX')
            mx = [str(r.exchange) for r in mx_records]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            mx = []

        try:
            a_records = dns.resolver.resolve(self.domain, 'A')
            a = [str(r.address) for r in a_records]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            a = []

        try:
            aaaa_records = dns.resolver.resolve(self.domain, 'AAAA')
            aaaa = [str(r.address) for r in aaaa_records]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            aaaa = []

        try:
            cname_records = dns.resolver.resolve(self.domain, 'CNAME')
            cname = [str(r.target) for r in cname_records]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            cname = []

        return {
            'statusCode': 200,
            'body': {
                'MX': mx,
                'A': a,
                'AAAA': aaaa,
                'CNAME': cname
            }
        }
