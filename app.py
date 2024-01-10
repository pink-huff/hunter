from os import environ as env
from flask import Flask, request, jsonify
import socket
import core.network.domain as domain
import core.network.url as url
import core.network.ip as ip
import core.network.shodan as shodan
import core.general.sanatise as sanatise
import core.thirdparty.mozzilaTLS as mozzila
import core.thirdparty.blackListChecker as blackListChecker

app = Flask(__name__)

## Domain

# Certs
@app.route('/certs', methods=['GET'])
def certs():
    domain_query = request.args.get('domain')
    if sanatise.is_domain(domain_query):
        cert_info = domain.SSLCertificateInfo(domain_query)
        certificate_data = cert_info.get_certificate_info()
        return {'data': certificate_data}
    else:
        return {'error': 'No domain provided'}, 400

# DNS
@app.route('/dns', methods=['GET'])
def dns_info():
    domain_query = request.args.get('domain')
    if sanatise.is_domain(domain_query):
        dns_info = domain.dnsInfo(domain_query)
        dns_result = dns_info.get_dns_info()
        return {'data': dns_result}
    else:
        return {'error': 'No domain provided'}, 400

# LetsEncrypt
@app.route('/letsencrypt', methods=['GET'])
def letsencrypt():
    domain_query = request.args.get('domain')
    if sanatise.is_domain(domain_query):
        lets_encrypt_checker = domain.letsEncryptInfo(domain_query)
        is_lets_encrypt = lets_encrypt_checker.check_lets_encrypt()
        return {'data': is_lets_encrypt}
    else:
        return {'error': 'No domain provided'}, 400
    
# Ports
@app.route('/ports', methods=['GET'])
def ports():
    domain_query = request.args.get('domain')

    if not sanatise.is_domain(domain_query):
        return jsonify({'error': 'No domain provided'}), 400

    try:
        socket.gethostbyname(domain_query)  # Validate the domain
    except socket.gaierror:
        return jsonify({'error': 'Invalid domain name'}), 400

    ports_info = domain.PortsInfo(domain_query)
    open_ports = ports_info.get_ports_info()

    if isinstance(open_ports, dict) and 'error' in open_ports:
        # Handling errors from get_ports_info
        return jsonify(open_ports), 500

    return jsonify({'domain': domain_query, 'open_ports': open_ports})

# ping
@app.route('/ping', methods=['GET'])
def ping():
    try:
        domain_query = request.args.get('domain')
        if sanatise.is_domain(domain_query):
            ping_info = domain.PingInfo(domain_query)
            ping_result = ping_info.ping_domain()
            # Include the domain in the response
            return {'domain': domain_query, 'ping': ping_result}
        else:
            return {'error': 'No domain provided'}, 400
    except Exception as e:
        return {'error': str(e)}, 500

# os
@app.route('/os', methods=['GET'])
def os_route():
    domain_query = request.args.get('domain')
    if sanatise.is_domain(domain_query):
        os_info_instance = domain.osInfo(domain_query)
        os_guess = os_info_instance.get_os_info()
        ttl = os_info_instance.ping_domain_ttl()
        if os_guess != "Unknown OS (No TTL)":
            # Assuming you want to include some nmap command or similar
            nmap_command = "nmap -O " + domain_query
            return {
                'nmapCommand': nmap_command,
                'ttl': ttl,
                'osGuess': os_guess
            }
        else:
            return {'error': 'Ping failed or OS could not be determined'}, 400
    else:
        return {'error': 'No host provided'}, 400

#whois
@app.route('/whois', methods=['GET'])
def whois():
    domain_query = request.args.get('domain')
    if sanatise.is_domain(domain_query):
        whois_info = domain.whoisInfo(domain_query)
        whois_result = whois_info.whois()
        return {'data': whois_result}
    else:
        return {'error': 'No domain provided'}, 400

# mx
@app.route('/mx', methods=['GET'])
def mx():
    domain_query = request.args.get('domain')
    if sanatise.is_domain(domain_query):
        mx_info = domain.mxInfo(domain_query)
        mx_result = mx_info.get_mx_info()
        return {'data': mx_result}
    else:
        return {'error': 'No domain provided'}, 400

# dns sec
@app.route('/dnssec', methods=['GET'])
def dnssec():
    domain_query = request.args.get('domain')
    if sanatise.is_domain(domain_query):
        dnssec_info = domain.dnsSecInfo(domain_query)
        dnssec_result = dnssec_info.get_dnssec_info()
        return {'data': dnssec_result}
    else:
        return {'error': 'No domain provided'}, 400
    
## URL
    
# Hosts
@app.route('/hosts', methods=['GET'])
def hosts():
    url_query = request.args.get('url')
    if sanatise.is_url(url_query):
        hosts_info = url.hostsInfo(url_query)
        host_result = hosts_info.get_hosts_info()
        return {'data': host_result}
    else:
        return {'error': 'No url provided'}, 400

# redirect check
@app.route('/redirect', methods=['GET'])
def redirect():
    url_query = request.args.get('url')
    if sanatise.is_url(url_query):
        redirect_info = url.redirectInfo(url_query)
        redirect_result = redirect_info.get_redirect_info()
        return {'data': redirect_result}
    else:
        return {'error': 'No domain provided'}, 400

# robots.txt
@app.route('/robots', methods=['GET'])
def robots():
    url_query = request.args.get('url')
    if url_query is None:
        return {'error': 'URL parameter is missing'}, 400

    if sanatise.is_url(url_query):
        robots_info = url.robotsInfo(url_query)
        robots_result = robots_info.get_robots_info()
        return {'data': robots_result}
    else:
        return {'error': 'Invalid URL provided'}, 400

# screenshot
@app.route('/screenshot', methods=['GET'])
def screenshot():
    url_query = request.args.get('url')
    if sanatise.is_url(url_query):
        screenshot_info = url.screenshotInfo(url_query)
        screenshot_result = screenshot_info.get_screenshot_info()
        return {'data': screenshot_result}
    else:
        return {'error': 'No url provided'}, 400

# sitemap
@app.route('/sitemap', methods=['GET'])
def sitemap():
    url_query = request.args.get('url')
    if sanatise.is_url(url_query):
        sitemap_info = url.sitemapInfo(url_query)
        sitemap_result = sitemap_info.get_sitemap_info()
        return {'data': sitemap_result}
    else:
        return {'error': 'No url provided'}, 400

# ssl
@app.route('/ssl', methods=['GET'])
def ssl():
    url_query = request.args.get('url')
    if sanatise.is_url(url_query):
        ssl_info = url.sslInfo(url_query)
        ssl_result = ssl_info.get_ssl_info()
        return {'data': ssl_result}
    else:
        return {'error': 'No url provided'}, 400
    
# url to ip
@app.route('/urltoip', methods=['GET'])
def urltoip():
    url_query = request.args.get('url')
    if sanatise.is_url(url_query):
        url_to_ip_info = url.urltoIpInfo(url_query)
        url_to_ip_result = url_to_ip_info.get_urltoip_info()
        return {'data': url_to_ip_result}
    else:
        return {'error': 'No url provided'}, 400

# cookies
@app.route('/cookies', methods=['GET'])
def cookies():
    url_query = request.args.get('url')
    if sanatise.is_url(url_query):
        # Example usage
        cookies_info = url.cookiesInfo(url_query)
        cookies_result = cookies_info.handler()
        return {'data': cookies_result}
    else:
        return {'error': 'No url provided'}, 400
    
# favicon
@app.route('/favicon', methods=['GET'])
def favicon():
    url_query = request.args.get('url')
    if url_query:  # Assuming you have a URL validation function
        favicon_info = url.faviconInfo(url_query)
        favicon_result = favicon_info.get_favicon_info()
        if favicon_result:
            return {'data': favicon_result}
        else:
            return {'error': 'Favicon not found'}, 404
    else:
        return {'error': 'No url provided'}, 400
## IP

# dig
@app.route('/dig', methods=['GET'])
def dig():
    ip_query = request.args.get('ip')
    if sanatise.is_ip(ip_query):
        dig_info = ip.digInfo(ip_query)
        dig_result = dig_info.get_dig()
        if dig_result is not None:
            return {'data': dig_result}
        else:
            return {'error': 'Failed to execute dig command'}, 500
    else:
        return {'error': 'No ip provided'}, 400

# traceroute
@app.route('/traceroute', methods=['GET'])
def traceroute():
    ip_query = request.args.get('ip')
    if sanatise.is_ip(ip_query):
        traceroute_info = ip.tracerouteInfo(ip_query)
        traceroute_result = traceroute_info.get_traceroute()
        return {'data': traceroute_result}
    else:
        return {'error': 'No ip provided'}, 400

# ip to asn
@app.route('/iptoasn', methods=['GET'])
def iptoasn():
    ip_query = request.args.get('ip')
    if sanatise.is_ip(ip_query):
        ip_to_asn_info = ip.ipASNInfo(ip_query)
        ip_to_asn_result = ip_to_asn_info.get_ip_asn()
        return {'data': ip_to_asn_result}
    else:
        return {'error': 'No ip provided'}, 400

# ip Geo
@app.route('/ipgeo', methods=['GET'])
def ipgeo():
    #https://myprojects.geoapify.com
    ip_query = request.args.get('ip')
    if sanatise.is_ip(ip_query):
        ip_geo_info = ip.ipGeoInfo(ip_query)
        ip_geo_result = ip_geo_info.get_ip_geo()
        if ip_geo_result:
            return jsonify(ip_geo_result)
        else:
            return jsonify({'error': 'Unable to retrieve GeoIP information'}), 500
    else:
        return jsonify({'error': 'No IP address provided'}), 400

# ip ping
@app.route('/ipping', methods=['GET'])
def ipping():
    ip_query = request.args.get('ip')
    if sanatise.is_ip(ip_query):
        ping_info = ip.pingIpInfo(ip_query)
        ping_result = ping_info.get_ping()
        return {'data': ping_result}
    else:
        return {'error': 'No ip provided'}, 400

## shodan 
    
# check subdomains
@app.route('/subdomains', methods=['GET'])
def subdomains():
    domain_query = request.args.get('domain')
    if sanatise.is_domain(domain_query):
        subdomains_info = shodan.subdomainsInfo(domain_query)
        subdomains_result = subdomains_info.get_subdomains_info()
        return {'data': subdomains_result}
    else:
        return {'error': 'No domain provided'}, 400

# reverse dns
@app.route('/reversedns', methods=['GET'])
def reversedns():
    ip_query = request.args.get('ip')
    if sanatise.is_ip(ip_query):
        reverse_dns_info = shodan.reverseDnsInfo(ip_query)
        reverse_dns_result = reverse_dns_info.get_reverse_dns_info()
        return {'data': reverse_dns_result}
    else:
        return {'error': 'No ip provided'}, 400

# General 
    
# is valid domain
@app.route('/isdomain', methods=['GET'])
def isdomain():
    domain_query = request.args.get('domain')
    if sanatise.is_domain(domain_query):
        is_domain = sanatise.is_domain(domain_query)
        return {f'{domain_query}': is_domain}
    else:
        return {'error': 'No domain provided'}, 400
# is ip
@app.route('/isip', methods=['GET'])
def isip():
    ip_query = request.args.get('ip')
    if sanatise.is_ip(ip_query):
        is_ip = sanatise.is_ip(ip_query)
        return {f'{ip_query}': is_ip}
    else:
        return {'error': 'No ip provided'}, 400

# is url
@app.route('/isurl', methods=['GET'])
def isurl():
    url_query = request.args.get('url')
    if sanatise.is_url(url_query):
        is_url = sanatise.is_url(url_query)
        return {f'{url_query}': is_url}
    else:
        return {'error': 'No url provided'}, 400
    
# third party 
    
# shodan host
@app.route('/shodanhost', methods=['GET'])
def shodanhost():
    ip_query = request.args.get('ip')
    if sanatise.is_ip(ip_query):
        shodan_host_info = shodan.shodanHostInfo(ip_query)
        shodan_host_result = shodan_host_info.get_shodan_host_info()
        return {'data': shodan_host_result}
    else:
        return {'error': 'No ip provided'}, 400

# black list checker
@app.route('/blacklistchecker', methods=['GET'])
def blacklistchecker():
    query = request.args.get('query')
    if not query:
        return {'error': 'No query provided'}, 400

    if sanatise.is_ip(query) or sanatise.is_email(query) or sanatise.is_domain(query):
        black_list_checker = blackListChecker.BlackListChecker(query)
        black_list_checker_result = black_list_checker.check()
        return {'data': black_list_checker_result}
    else:
        return {'error': 'Invalid query format'}, 400

# mozilla tls
@app.route('/mozillatls', methods=['GET'])
def mozillatls():
    url_query = request.args.get('url')
    if sanatise.is_url(url_query):
        mozilla_tls_checker = mozzila.MozillaTLSInfo(url_query)
        mozilla_tls_result = mozilla_tls_checker.check()
        return {'data': mozilla_tls_result}
    else:
        return {'error': 'No url provided'}, 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=env.get("PORT", 5001))