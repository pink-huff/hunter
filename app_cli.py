# import libraries
import asyncio
import argparse

# Import general functions
import core.general.banner as banner
import core.network.domain as domain
import core.network.shodan as shodan
import core.network.network_scanner as network_scanner
from core.general.sanatise import is_ip, is_domain
# News
from core.news.gdelt import GDELT
from core.news.wikipedia import WikipediaAPI


# Main function
def main(queries, output_file=None):
    processed_queries = set()  # Set to track processed queries

    for query in queries:
        if query not in processed_queries:
            processed_queries.add(query)  # Add the query to the set to mark it as processed

            output = []
            if output_file:
                filename = f"{output_file}_{query}.txt"
                # Example usage of write_to_file instead of print
                output.append(f"Results for {query}:\n")
            
            if is_domain(query):

                print(f"{query} is a valid domain")
                output.append(f"{query} is a valid domain")
                # Process as domain name
                url = f"https://www.{query}"
                print(f"\nQuerying Domain: {query}")
                output.append(f"\nQuerying Domain: {query}")
                print(f"\n{url}")
                output.append(f"\n{url}")

                # Cert.sh
                print(f"\nCert.sh for {query}")
                output.append(f"\nCert.sh for {query}")
                for row in domain.certSH(query):
                    print(row)
                    output.append(row)

                # Subdomains
                print(f"\nSubdomains:")
                output.append(f"\nSubdomains:")
                subdomains = shodan.check_subdomains(query)
                if isinstance(subdomains, list) and subdomains:
                    print(f"Subdomains of {query}:")
                    output.append(f"Subdomains of {query}:")
                    for subdomain in subdomains:
                        print(subdomain)
                        output.append(subdomain)
                else:
                    print(f"No subdomains found for {query}.")
                    output.append(f"No subdomains found for {query}.")
                    
            elif is_ip(query):
                # Process as IP address
                # Process as IP address
                print(f"\nQuerying IP: {query}")
                output.append(f"\nQuerying IP: {query}")
                print(f"\nTraceroute: {query}")
                output.append(f"\nTraceroute: {query}")
                hostnames = shodan.reverse_dns_with_shodan(query)
            
                if isinstance(hostnames, list) and hostnames:
                    print(f"Reverse DNS lookup for {query}: {hostnames}")
                    output.append(f"Reverse DNS lookup for {query}: {hostnames}")
                    main(hostnames)  # Recursive call to main with the hostnames
                else:
                    print(f"No hostnames found for IP {query}")
                    output.append(f"No hostnames found for IP {query}")

            else:
                # Process as domain name
                url = f"https://www.{query}"
                print(f"\nQuerying Domain: {query}")
                output.append(f"\nQuerying Domain: {query}")
                print(f"\n{url}")
                output.append(f"\n{url}")

                # Subdomains
                print(f"\nSubdomains:")
                output.append(f"\nSubdomains:")
                subdomains = shodan.check_subdomains(query)
                if isinstance(subdomains, list) and subdomains:
                    print(f"Subdomains of {query}:")
                    output.append(f"Subdomains of {query}:")
                    for subdomain in subdomains:
                        print(subdomain)
                        output.append(subdomain)
                else:
                    print(f"No subdomains found for {query}.")
                    output.append(f"No subdomains found for {query}.")

            # Network Scanning
            print(f"\nActive Scanning:")
            output.append(f"\nActive Scanning:")
            nmap_command, ttl, ping = domain.check_ping(query)
            os_type = domain.check_os(ttl)
            print(f"Nmap Command: {nmap_command}, TTL: {ttl}, OS Type: {os_type}")
            output.append(f"Nmap Command: {nmap_command}, TTL: {ttl}, OS Type: {os_type}")
            
            # Screenshots with error handling
            try:
                screenshot_result = domain.screenshot(url)
                print(f"\nScreenshot of website (First 10 chars): {screenshot_result[:10]}")
                output.append(f"\nScreenshot of website (First 10 chars): {screenshot_result[:10]}")
            except Exception as e:
                print(f"Error taking screenshot: {e}")
                output.append(f"Error taking screenshot: {e}")
                pass # Ignore error

            # Redirects
            print(f"\nRedirects:")
            output.append(f"\nRedirects:")
            try:
                print(f"Redirects to: {domain.redirect(url)}")
                output.append(f"Redirects to: {domain.redirect(url)}")
                print(domain.redirect(url))
                output.append(domain.redirect(url))
            except Exception as e:
                print(f"Error checking redirects: {e} {url}")
                output.append(f"Error checking redirects: {e} {url}")
                pass

            # SSL Check
            print(f"\nSSL Check:")
            output.append(f"\nSSL Check:")
            print(domain.sslcheck(url))
            output.append(domain.sslcheck(url))

            # DNS Info
            print(f"\nDNS Info:")
            output.append(f"\nDNS Info:")
            print(domain.get_dns_info(url))
            output.append(domain.get_dns_info(url))

            # URL to IP
            print(f"\nURL to IP:")
            output.append(f"\nURL to IP:")
            print(domain.getIP(url))
            output.append(domain.getIP(url))

            # Sitemap
            print(f"\nSitemap:")
            output.append(f"\nSitemap:")
            print(domain.getSitemap(url))
            output.append(domain.getSitemap(url))

            # Hosts
            print(f"\nHosts:")
            output.append(f"\nHosts:")
            print(domain.getHosts(url))
            output.append(domain.getHosts(url))

            # Ports
            print(f"\nPorts:")
            output.append(f"\nPorts:")
            print(asyncio.run(domain.getPorts(url)))
            output.append(asyncio.run(domain.getPorts(url)))

        else:
            print(f"Query for {query} already processed, skipping.")
            output.append(f"Query for {query} already processed, skipping.")
            
if __name__ == "__main__":

    print(banner.print_banner())
    parser = argparse.ArgumentParser(description="Recon tool")
    parser.add_argument("--domain", nargs="*", help="Domains to search for (space-separated)")
    parser.add_argument("--ip", nargs="*", help="IP addresses to search for (space-separated)")

    args = parser.parse_args()

    queries = []
    if args.domain:
        queries.extend(args.domain)
    if args.ip:
        queries.extend(args.ip)

    if not queries:
        print("Please provide at least one domain with --domain <domain> or one IP address with --ipAddress <ip>")
    else:
        main(queries)