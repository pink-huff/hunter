# Project Documentation


## Documentation for `sanatise.py`


### is_ip
```python
Validates if the input string is a valid ip address.

Args:
domain (str): The ip address to validate.

Returns:
bool: True if the ip address is valid, False otherwise.
```

### is_domain
```python
Validates if the input string is a valid domain name.

Args:
domain (str): The domain name to validate.

Returns:
bool: True if the domain name is valid, False otherwise.
```

### is_url
```python
Validates if the input string is a valid url.

Args:
url (str): The url to validate.

Returns:
bool: True if the url is valid, False otherwise.
```

### is_email
```python
Validates if the input string is a valid email address.

Args:
email (str): The email address to validate.

Returns:
bool: True if the email address is valid, False otherwise.
```

## Documentation for `errorresponse.py`


### error_response
```python
Creates a standardized error response.

Args:
message (str): A descriptive error message.
status_code (int, optional): The HTTP status code associated with the error. 
                             Defaults to 500 (Internal Server Error).

Returns:
dict: A dictionary containing the status code and a JSON-encoded body with the error message.
```

## Documentation for `banner.py`


### print_banner
```python
Prints the ASCII art banner for the 'Hunter' tool along with its creation and version information.

This function does not take any arguments or return any value. It is purely for display purposes when called. 
The printed information includes an ASCII art representation of the word 'Hunter', author, and version number.

The banner is designed to be displayed at the beginning of the program to provide users with immediate visual feedback about the tool they are using.

Args:
None

Returns:
None
```

## Documentation for `domain.py`


### get_html_content
```python
Retrieves the HTML content from the crt.sh website for the given domain.

Returns:
str: The HTML content of the crt.sh page corresponding to the queried domain.
```

### parse_html_content
```python
Parses the HTML content from the crt.sh website to extract certificate information.

Args:
html_content (str): HTML content as retrieved from the crt.sh website.

Returns:
list of dicts: A list where each dictionary contains information about one SSL certificate.
```

### get_certificate_info
```python
Retrieves and parses SSL certificate information for the domain.

Returns:
list of dicts: A list of dictionaries with parsed SSL certificate data.
```

### get_dns_info
```python
Retrieves DNS information for a specified hostname.

Args:
hostname (str): The hostname for which DNS information is requested. Can handle both raw hostnames and URLs.

Returns:
dict: A dictionary containing various DNS records (A, AAAA, MX, TXT, NS, CNAME, SOA, SRV, PTR) if successful,
    or an error message and a status code of 500 in case of failure.
```

### get_hosts_info
```python
Checks if the given URL is compatible with HSTS preload requirements.

Args:
url (str): The URL to check for HSTS preload compatibility.

Returns:
dict: A dictionary containing the status code, a message describing the HSTS compatibility,
    and additional details like whether the site is compatible, the HSTS header if present,
    and specific reasons for incompatibility if any.
```

### check_lets_encrypt
```python
Checks if the domain associated with this instance is registered with Let's Encrypt.

Returns:
bool: True if the domain is registered with Let's Encrypt, False otherwise.
```

### get_ports_info
```python
Checks if the given URL is compatible with HSTS preload requirements.

Args:
url (str): The URL to check for HSTS preload compatibility.

Returns:
dict: A dictionary containing the status code, a message describing the HSTS compatibility,
    and additional details like whether the site is compatible, the HSTS header if present,
    and specific reasons for incompatibility if any.
```

### ping_domain
```python
Checks if the specified host responds to a ping request.

Args:
host (str): The hostname or IP address to ping.

Returns:
bool: True if the host responds to a ping request, False otherwise.
```

### ping_domain_ttl
```python
Checks if the specified host responds to a ping request and returns the TTL value and a base Nmap command.

Args:
host (str): The hostname or IP address to ping.

Returns:
tuple: A tuple containing the Nmap command, the TTL value if the host responds, and a boolean indicating 
    if the ping was successful. Returns None for TTL if the host does not respond or an error occurs.
```

### get_os_info
```python
Retrieves the likely operating system of a host based on the TTL value.

Args:
ttl (str): The TTL (Time To Live) value as a string, typically obtained from a ping response.

Returns:
str: A string indicating the likely operating system of the host based on the TTL value, 
    or 'Unknown OS' if the TTL is not indicative of a common operating system.
```

### whois
```python
Retrieves WHOIS information for a given domain.

Args:
domain (str): The domain name for which to retrieve WHOIS information.

Returns:
dict: A dictionary containing the status code and either the WHOIS information (if found) or an error message.
```

### get_dnssec_info
```python
Retrieves DNSSEC information for a specified hostname.

Args:
hostname (str): The hostname for which DNSSEC information is requested. Can handle both raw hostnames and URLs.

Returns:
dict: A dictionary containing various DNSSEC records (DS, DNSKEY, NSEC, NSEC3, RRSIG) if successful,
    or an error message and a status code of 500 in case of failure.
```

### get_mx_info
```python
Retrieves MX information for a specified hostname.

Args:
hostname (str): The hostname for which MX information is requested. Can handle both raw hostnames and URLs.

Returns:
dict: A dictionary containing various MX records (MX, A, AAAA, CNAME) if successful,
    or an error message and a status code of 500 in case of failure.
```

## Documentation for `url.py`


### get_hosts_info
```python
Checks if the given URL is compatible with HSTS preload requirements.

Args:
url (str): The URL to check for HSTS preload compatibility.

Returns:
dict: A dictionary containing the status code, a message describing the HSTS compatibility,
    and additional details like whether the site is compatible, the HSTS header if present,
    and specific reasons for incompatibility if any.
```

### get_redirect_info
```python
Checks for and traces HTTP redirections for a given URL.

Args:
url (str): The URL to check for redirection.

Returns:
dict: A dictionary containing information about the redirection process, such as a message indicating
    if redirection occurred, the redirection history (if any), and the final destination URL.
    In case of an error or timeout, the dictionary contains an error message.
```

### get_robots_info
```python
Retrieves the robots.txt file for a given URL.

Args:
url (str): The URL to retrieve the robots.txt file for.

Returns:
dict: A dictionary containing the status code, and the contents of the robots.txt file.
```

### get_screenshot_info
```python
Takes a screenshot of a webpage at a given URL and returns the screenshot as a base64 encoded string.

Args:
url (str): The URL of the webpage to take a screenshot of.

Returns:
dict: A dictionary containing the status code and either a base64 encoded string of the screenshot
    (if successful) or an error message.
```

### get_sitemap_info
```python
Retrieves the sitemap of a website from its robots.txt file and parses it.

Args:
url (str): The base URL of the website from which to retrieve the sitemap.

Returns:
dict: A dictionary containing the status code and either the parsed sitemap (if found) or an error message.
```

### get_ssl_info
```python
Checks and retrieves the SSL certificate information of the given URL.

Args:
url (str): The URL to check for SSL certificate validity.

Returns:
dict: A dictionary containing the status code and either the SSL certificate details in JSON format 
    (if successful) or an error message.
```

### get_urltoip_info
```python
Resolves the IP address of the hostname in the given URL.

Args:
url (str): The URL whose IP address needs to be resolved.

Returns:
dict: A dictionary containing the status code and either the resolved IP address and its family (IPv4)
    or an error message.
```

### get_cookies_info
```python
Retrieves the cookies set by a given URL.

Args:
url (str): The URL to retrieve the cookies for.

Returns:
dict: A dictionary containing the status code and either the cookies set by the URL or an error message.
```

### handler
```python
Main handler function
```

## Documentation for `ip.py`


### get_dig
```python
Executes the 'dig' command to query DNS information for the specified IP address.

Args:
ip (str): The IP address to query DNS information for.

Returns:
str or None: The output of the dig command if successful, or None if an error occurs.
```

### get_traceroute
```python
Performs a traceroute to the specified IP address.

Args:
ip_address (str): The IP address or hostname to trace.

Returns:
str: The output of the traceroute command.
```

### get_ip_asn
```python
Executes the 'whois' command to query ASN information for the specified IP address.

Args:
ip (str): The IP address to query ASN information for.

Returns:
str or None: The output of the whois command if successful, or None if an error occurs.
```

### get_ip_geo
```python
Executes the 'geoiplookup' command to query GeoIP information for the specified IP address.

Args:
ip (str): The IP address to query GeoIP information for.

Returns:
str or None: The output of the geoiplookup command if successful, or None if an error occurs.
```

### get_ping
```python
Executes the 'ping' command to query ping information for the specified IP address.

Args:
ip (str): The IP address to query ping information for.

Returns:
str or None: The output of the ping command if successful, or None if an error occurs.
```

## Documentation for `network_scanner.py`


### run_command
```python
Executes a given command in the shell and returns its output.

Args:
command (str): The command to be executed.

Returns:
str or None: The standard output from the executed command, or None if an error occurs.
```

### perform_network_scan
```python
Performs a network scan on the given host.

Args:
host (str): The target host IP or URL.

Returns:
str or None: The result of the network scan, or None if an error occurs.
```

### perform_port_scan
```python
Performs a port scan on the given host.

Args:
host (str): The target host IP or URL.

Returns:
str or None: The result of the port scan, or None if an error occurs.
```

### perform_scan
```python
Performs a scan on the given host based on the specified scan type.

Args:
host (str): The target host IP or URL.
scan_type (str): The type of scan ('network' or 'port').

Returns:
str or None: The result of the specified scan, or None if an error occurs or the scan type is unknown.
```

### parse_arguments
```python
Parses command-line arguments.

Returns:
Namespace: An argparse Namespace containing the parsed arguments.
```

### main
```python
Main function that orchestrates the network scanning process based on command-line arguments.
```

## Documentation for `shodan.py`


### get_subdomains_info
```python
Searches for subdomains of the given domain using the Shodan API.

Args:
domain_name (str): The domain name for which subdomains are to be searched.

Returns:
list or str: A list of subdomains if the search is successful, or an error message string if an API error occurs.
```

### get_reverse_dns_info
```python
Performs a reverse DNS lookup for the specified IP address using the Shodan API.

Args:
ip_address (str): The IP address for which the reverse DNS lookup is to be performed.

Returns:
list or str: A list of hostnames associated with the IP address if found, a list containing 'No hostnames found' 
             if no hostnames are associated, or an error message string if an API or other error occurs.
```

### get_shodan_host_info
```python
Retrieves host information for the specified IP address using the Shodan API.

Args:
ip_address (str): The IP address for which host information is to be retrieved.

Returns:
dict or str: A dictionary containing host information if successful, or an error message string if an API or other error occurs.
```

## Documentation for `gdelt.py`


### details
```python
Provides details about the GDELT source.

Returns:
dict: A dictionary containing details such as source name, title, color, description, and available methods.
```

### call
```python
Processes a query to the GDELT API.

Args:
query (dict): A dictionary containing query parameters and values.

Returns:
dict: A dictionary containing the response from the GDELT API, including error messages, results, and query status.
```

### call_geo
```python
Processes a geographic query to the GDELT API.

Args:
query (dict): A dictionary containing geographic query parameters.
response (dict): The initial response dictionary to be updated with the results.

Returns:
dict: An updated response dictionary with the results from the geographic query.
```

### call_document
```python
Processes a document search query to the GDELT API.

Args:
query (dict): A dictionary containing document search query parameters.
response (dict): The initial response dictionary to be updated with the results.

Returns:
dict: An updated response dictionary with the results from the document search query.
```

## Documentation for `wikipedia.py`


### __init__
```python
Initializes the WikipediaAPI class.
```

### search_article
```python
Searches for articles on Wikipedia matching the given query.

Args:
query (str): The search query.

Returns:
list: A list of search results, or None if an error occurs.
```

### get_summary
```python
Retrieves a summary of the first search result for a given query.

Args:
query (str): The search query.

Returns:
str: A summary of the first search result, an error message if no summary is found, or if no search results are found.
```

### retrieve_summary
```python
Retrieves a summary for a given Wikipedia page title.

Args:
page_title (str): The title of the Wikipedia page.

Returns:
str or None: A summary of the specified page, None if an error occurs or if the page doesn't have a summary.
```

## Documentation for `mozzilaTLS.py`


### __init__
```python
Initializes the MozillaTLS with a URL.

Parameters:
    url (str): The URL to be checked against the Mozilla TLS Observatory.
```

### check
```python
Checks if the provided URL is on the Mozilla TLS Observatory by making an API call to the Mozilla TLS Observatory.

The method performs a POST request to the API with the URL. The response, if successful (HTTP 200), is returned as a JSON object. In case of failure,
an error message with the status code or exception details is returned.

Returns:
    dict: A dictionary with the API response data if the request is successful,
          or an error message and status code in case of a failure.

Raises:
    Exception: If there is an issue with the network or other unexpected errors during the API call.
```

## Documentation for `blackListChecker.py`


### __init__
```python
Initializes the BlackListChecker with a query.

Parameters:
    query (str): The query string to be checked against the blacklist.
```

### check
```python
Checks if the provided query is on the blacklist by making an API call to blacklistchecker.com.

The method performs a GET request to the API with the query. HTTP Basic Authentication is used with
an API key. The response, if successful (HTTP 200), is returned as a JSON object. In case of failure,
an error message with the status code or exception details is returned.

Returns:
    dict: A dictionary with the API response data if the request is successful,
          or an error message and status code in case of a failure.

Raises:
    Exception: If there is an issue with the network or other unexpected errors during the API call.
```

## Documentation for `virustotal.py`


## Documentation for `archiveOrg.py`


## Documentation for `wappalyzer.py`

