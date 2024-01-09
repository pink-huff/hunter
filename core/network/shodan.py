from core.general.errorresponse import error_response
from dotenv import load_dotenv
import shodan
import os

# Load Shodan API key from .env file
# Load the .env file
load_dotenv()
shodan_api_key = os.getenv('SHODAN_API')
# Initialize the Shodan API client
api = shodan.Shodan(shodan_api_key)

class subdomainsInfo:
    def __init__(self, domain):
        self.domain = domain

    def get_subdomains_info(self):
        """
        Searches for subdomains of the given domain using the Shodan API.

        Args:
        domain_name (str): The domain name for which subdomains are to be searched.

        Returns:
        list or str: A list of subdomains if the search is successful, or an error message string if an API error occurs.
        """
        try:
            # Search for subdomains of the given domain
            query = f'hostname:{self.domain}'
            results = api.search(query)
            
            # Extract and return the list of subdomains
            subdomains = []
            for result in results['matches']:
                hostnames = result.get('hostnames', [])
                subdomains.extend(hostnames)
            
            return subdomains
        except shodan.APIError as e:
            return error_response(e)

class reverseDnsInfo:
    def __init__(self, ip):
        self.ip = ip

    def get_reverse_dns_info(self):
        """
        Performs a reverse DNS lookup for the specified IP address using the Shodan API.

        Args:
        ip_address (str): The IP address for which the reverse DNS lookup is to be performed.

        Returns:
        list or str: A list of hostnames associated with the IP address if found, a list containing 'No hostnames found' 
                     if no hostnames are associated, or an error message string if an API or other error occurs.
        """

        try:

            # Perform a reverse DNS lookup using Shodan
            host_info = api.host(self.ip)

            # Check if hostnames are available and return them
            hostnames = host_info.get('hostnames', [])
            if hostnames:
                return hostnames
            else:
                return ['No hostnames found']
        except shodan.APIError as e:
            return error_response(e)
        except Exception as e:
            return error_response(e)

class shodanHostInfo:
    def __init__(self, ip):
        self.ip = ip

    def get_shodan_host_info(self):
        """
        Retrieves host information for the specified IP address using the Shodan API.

        Args:
        ip_address (str): The IP address for which host information is to be retrieved.

        Returns:
        dict or str: A dictionary containing host information if successful, or an error message string if an API or other error occurs.
        """
        try:
            # Retrieve host information using Shodan
            host_info = api.host(self.ip)

            # Return the host information
            return host_info
        except shodan.APIError as e:
            return error_response(e)
        except Exception as e:
            return error_response(e)