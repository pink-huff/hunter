from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from core.general.errorresponse import error_response
from urllib.parse import urlparse
import socket
import json
import base64
from OpenSSL import SSL
import time
import xmltodict
import requests
import re

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

class redirectInfo:
    def __init__(self, url):
        self.url = url

    def get_redirect_info(self):
        """
        Checks for and traces HTTP redirections for a given URL.

        Args:
        url (str): The URL to check for redirection.

        Returns:
        dict: A dictionary containing information about the redirection process, such as a message indicating
            if redirection occurred, the redirection history (if any), and the final destination URL.
            In case of an error or timeout, the dictionary contains an error message.
        """

        if not self.url:
            return {'error': 'URL query parameter is required'}, 400

        try:
            response = requests.get(self.url, allow_redirects=False, timeout=4)  # Add a timeout of 4 seconds

            if 300 <= response.status_code < 400:
                redirection_history = []
                for resp in response.history:
                    redirection_history.append({
                        'status_code': resp.status_code,
                        'url': resp.url
                    })

                final_destination = {
                    'status_code': response.status_code,
                    'url': response.headers.get('Location', response.url)
                }

                return {
                    'message': 'Request was redirected',
                    'redirection_history': redirection_history,
                    'final_destination': final_destination
                }
            else:
                return {'message': 'No redirection occurred'}

        except requests.Timeout:
            return {'error': 'Request timed out, likely no redirection occurred'}
        except Exception as e:
            return {'error': f'Unexpected error occurred: {str(e)}'}

class robotsInfo:
    def __init__(self, domain):
        self.domain = domain

    def get_robots_info(self):
        """
        Retrieves the robots.txt file for a given URL.

        Args:
        url (str): The URL to retrieve the robots.txt file for.

        Returns:
        dict: A dictionary containing the status code, and the contents of the robots.txt file.
        """
        if not self.domain:
            return error_response('Missing domain parameter.')

        try:
            response = requests.get(self.domain + '/robots.txt')
            return {
                'statusCode': 200,
                'body': response.text
            }
        except Exception as error:
            return error_response(f'Error making request: {error}')

class screenshotInfo:
    def __init__(self, url):
        self.url = url

    def get_screenshot_info(self):
        """
        Takes a screenshot of a webpage at a given URL and returns the screenshot as a base64 encoded string.

        Args:
        url (str): The URL of the webpage to take a screenshot of.

        Returns:
        dict: A dictionary containing the status code and either a base64 encoded string of the screenshot
            (if successful) or an error message.
        """
        if not self.url:
            return error_response('URL query parameter is required', 400)

        try:
            # Setup Chrome options
            options = Options()
            options.add_argument("--headless")

            # Create webdriver object
            driver = webdriver.Chrome(options=options)

            with driver:
                # Get webpage
                driver.get(self.url)

                # Take screenshot directly to memory
                screenshot = driver.get_screenshot_as_png()

            # Encode screenshot in base64
            encoded_string = base64.b64encode(screenshot).decode("utf-8")

            return {
                'statusCode': 200,
                'body': encoded_string
            }

        except Exception as e:
            return error_response(f'Unexpected error occurred: {str(e)}')
        
class sitemapInfo:
    def __init__(self, url):
        self.url = url

    def get_sitemap_info(self):
        """
        Retrieves the sitemap of a website from its robots.txt file and parses it.

        Args:
        url (str): The base URL of the website from which to retrieve the sitemap.

        Returns:
        dict: A dictionary containing the status code and either the parsed sitemap (if found) or an error message.
        """

        base_url = self.url.lstrip('http://').lstrip('https://')
        url = f'http://{base_url}' if not base_url.startswith('http') else base_url
        sitemap_url = None

        try:
            # Fetch robots.txt
            robots_res = requests.get(f'{url}/robots.txt')
            robots_txt = robots_res.text.split('\n')

            for line in robots_txt:
                if line.startswith('Sitemap:'):
                    sitemap_url = line.split(' ')[1]

            if not sitemap_url:
                return {
                    'statusCode': 404,
                    'body': {'error': 'Sitemap not found in robots.txt'}
                }

            # Fetch sitemap
            sitemap_res = requests.get(sitemap_url)
            sitemap = xmltodict.parse(sitemap_res.text)

            return {
                'statusCode': 200,
                'body': sitemap
            }
        except Exception as error:
            return {
                'statusCode': 500,
                'body': {'error': str(error)}
            }

class sslInfo:
    def __init__(self, url):
        self.url = url

    def get_ssl_info(self):
        """
        Checks and retrieves the SSL certificate information of the given URL.

        Args:
        url (str): The URL to check for SSL certificate validity.

        Returns:
        dict: A dictionary containing the status code and either the SSL certificate details in JSON format 
            (if successful) or an error message.
        """
        if not self.url:
            return error_response('URL query parameter is required', 400)

        try:
            # Try to connect to the server and fetch the certificate
            parsed_url = urlparse(self.url)
            host = parsed_url.hostname
            port = parsed_url.port if parsed_url.port else 443

            # Establish a socket connection to the server
            context = SSL.Context(SSL.SSLv23_METHOD)
            sock = SSL.Connection(context, socket.create_connection((host, port)))
            sock.set_tlsext_host_name(host.encode())
            sock.set_connect_state()
            sock.do_handshake()

            cert = sock.get_peer_certificate()
            if cert is None:
                return error_response("No certificate presented by the server.")

            # Convert the certificate to a dictionary
            cert_dict = {}
            for component in cert.get_subject().get_components():
                cert_dict[component[0].decode('utf-8')] = component[1].decode('utf-8')

            return {
                'statusCode': 200,
                'body': json.dumps(cert_dict)
            }

        except Exception as e:
            return error_response(f'Unexpected error occurred: {str(e)}')

class urltoIpInfo:
    def __init__(self, url):
        self.url = url

    def get_urltoip_info(self):
        """
        Resolves the IP address of the hostname in the given URL.

        Args:
        url (str): The URL whose IP address needs to be resolved.

        Returns:
        dict: A dictionary containing the status code and either the resolved IP address and its family (IPv4)
            or an error message.
        """
        if not self.url:
            return error_response('Address parameter is missing.', 444)

        address = urlparse(self.url).hostname

        try:
            ip = socket.gethostbyname(address)
            return {
                'statusCode': 200,
                'body': {'ip': ip, 'family': 'IPv4'}
            }
        except socket.gaierror as err:
            return error_response(str(err), 444)

class cookiesInfo:
    def __init__(self, url):
        self.url = url

    def get_cookies_info(self):
        """
        Retrieves the cookies set by a given URL.

        Args:
        url (str): The URL to retrieve the cookies for.

        Returns:
        dict: A dictionary containing the status code and either the cookies set by the URL or an error message.
        """
        # Setup Chrome options
        options = Options()
        options.add_argument("--headless")
        # Create webdriver object
        driver = webdriver.Chrome(options=options)

        try:
            driver.get(self.url)
            # Wait for the page to load
            time.sleep(3)
            cookies = driver.get_cookies()
            return cookies
        finally:
            driver.quit()
    
    def handler(self):
        """
        Main handler function
        """
        header_cookies = None
        client_cookies = None

        try:
            response = requests.get(self.url, allow_redirects=True)
            header_cookies = response.cookies.get_dict()
        except requests.RequestException as e:
            return {'error': str(e)}

        try:
            client_cookies = self.get_cookies_info()
        except Exception as e:
            client_cookies = None

        if not header_cookies and (not client_cookies or len(client_cookies) == 0):
            return {'skipped': 'No cookies'}

        return {'header_cookies': header_cookies, 'client_cookies': client_cookies}