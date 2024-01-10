# Network Recon
An app (cli or api) to run tools for OSINT, networking and Ethical Hacking

## About

Currently in Alpha. 

### Network Recon 

### Social Media 

### General OSINT

## CLI
### Install 

`pip install -r requirments.txt`

### Setup 

create .env file with credentials

`SHODAN_API="XXX"`

`BLACKLIST_CHECKER_API="XXX"`

`VIRUS_TOTAL_API="XXX"`

`GEO_IP_API="XXX"`

### Use app_cli.py

`python app_cli.py --domain example.com`

`python app_cli.py --ip 192.168.1.1`

## Docker
### Build and run docker 
#### Build

`docker build -t hunter:latest .`

#### Run and set env 

    docker run -p 5001:5001 \
    -e SHODAN_API="XXX" \
    -e BLACKLIST_CHECKER_API="XXX" \
    -e VIRUS_TOTAL_API="XXX" \
    -e GEO_IP_API="XXX" \
    hunter:latest

## Python Server
### app.py 

`gunicorn -w 4 app:app`

## Endpoints

### Domain-Related Endpoints

- `/certs`: Fetches SSL certificate information for a given domain.
- `/dns`: Retrieves DNS information for a specified domain.
- `/letsencrypt`: Checks if a domain uses Let's Encrypt for its SSL.
- `/ports`: Lists open ports on a domain.
- `/ping`: Pings a domain and returns the result.
- `/os`: Guesses the operating system of a domain based on network characteristics.
- `/whois`: Provides WHOIS information for a domain.
- `/dnssec`: Retrieve information about a domain DNSSEC 
- `/mx`: Retrieves MX info about a domain

### URL-Related Endpoints

- `/hosts`: Retrieves host information from a URL.
- `/redirect`: Checks for and returns redirect information for a URL.
- `/robots`: Fetches the robots.txt file from a URL.
- `/screenshot`: Takes and returns a screenshot of a webpage from a URL.
- `/sitemap`: Retrieves the sitemap from a URL.
- `/ssl`: Fetches SSL information related to a URL.
- `/urltoip`: Converts a URL to its corresponding IP address.
- `/cookies`: Fetches cookies from a given url
- `/favicon`: Fethces favicon from a url

### IP-Related Endpoints

- `/dig`: Executes a DIG command for an IP address.
- `/traceroute`: Performs a traceroute to an IP address.
- `/iptoasn`: Peforms IP asn
- `/ipgeo`: Uses third party API for IP to geo

### Shodan-Related Endpoints

- `/subdomains`: Finds subdomains for a given domain using Shodan.
- `/reversedns`: Performs reverse DNS lookup using Shodan.
- `/shodanhost`: Retrieves host information from Shodan for a given IP.

### Third party API
- `/blacklistcheck`: Uses black list checker to query email, domain or IP
- `/mozzilaTLS`: Uses Mozilla's TLS Observatory API to inspect the TLS configurations of a web domains.

# DISCLAIMER
**Always obey the laws**