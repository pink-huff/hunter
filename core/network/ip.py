from dotenv import load_dotenv
from bs4 import BeautifulSoup as bs4
import pandas as pd
import subprocess
import platform
import requests
import os

# Load the .env file
load_dotenv()
api = os.getenv('GEO_IP_API')

class digInfo:
    def __init__(self, ip):
        self.ip = ip

    def get_dig(self):
        """
        Executes the 'dig' command to query DNS information for the specified IP address.

        Args:
        ip (str): The IP address to query DNS information for.

        Returns:
        str or None: The output of the dig command if successful, or None if an error occurs.
        """
        try:
            # Run dig command
            dig = subprocess.check_output(['dig', self.ip], stderr=subprocess.STDOUT)
            # Return dig result as string
            return dig.decode('utf-8')
        except subprocess.CalledProcessError:
            # Return None on error
            return None

class tracerouteInfo:
    def __init__(self, ip):
        self.ip = ip

    def get_traceroute(self):
        """
        Performs a traceroute to the specified IP address.

        Args:
        ip_address (str): The IP address or hostname to trace.

        Returns:
        str: The output of the traceroute command.
        """
        # Determine the command based on the operating system
        traceroute_cmd = 'traceroute'
        if platform.system().lower() == 'windows':
            traceroute_cmd = 'tracert'

        try:
            # Run the traceroute command
            result = subprocess.run([traceroute_cmd, self.ip], check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            return f"Error during traceroute execution: {e.output}"
        except Exception as e:
            return f"Error during traceroute execution: {e}"

class ipASNInfo:
    def __init__(self, ip):
        self.ip = ip

    def get_ip_asn(self):
        """
        Executes the 'whois' command to query ASN information for the specified IP address.

        Args:
        ip (str): The IP address to query ASN information for.

        Returns:
        str or None: The output of the whois command if successful, or None if an error occurs.
        """
        try:
            # Run whois command
            whois = subprocess.check_output(['whois', self.ip], stderr=subprocess.STDOUT)
            # Return whois result as string
            return whois.decode('utf-8')
        except subprocess.CalledProcessError:
            # Return None on error
            return None

class ipGeoInfo:
#https://www.freecodecamp.org/news/how-to-get-location-information-of-ip-address-using-python/
    def __init__(self, ip):
        self.ip = ip

    def get_ip_geo(self):
        """
        Executes the 'geoiplookup' command to query GeoIP information for the specified IP address.

        Args:
        ip (str): The IP address to query GeoIP information for.

        Returns:
        str or None: The output of the geoiplookup command if successful, or None if an error occurs.
        """
        try:
            response = requests.get(f'https://api.geoapify.com/v1/ipinfo?ip={self.ip}&apiKey={api}').json()
            return response
        except requests.RequestException as e:
            # You can log the error here if needed
            return None

class pingIpInfo:
    def __init__(self, ip):
        self.ip = ip

    def get_ping(self):
        """
        Executes the 'ping' command to query ping information for the specified IP address.

        Args:
        ip (str): The IP address to query ping information for.

        Returns:
        str or None: The output of the ping command if successful, or None if an error occurs.
        """
        try:
            # Run ping command
            ping = subprocess.check_output(['ping', self.ip], stderr=subprocess.STDOUT)
            # Return ping result as string
            return ping.decode('utf-8')
        except subprocess.CalledProcessError:
            # Return None on error
            return None

class ipTorrentActivity:
    def __init__(self, ip):
        self.ip = ip

    def get_torrent_activity(self):
        """
        Queries the IP address in the torrent network to check if it is active.

        Args:
        ip (str): The IP address to check for torrent activity.

        Returns:
        str: A message indicating whether the IP address is active in the torrent network.
        """
        # Query the IP address in the torrent network
        response = requests.get(f'https://iknowwhatyoudownload.com/en/peer/?ip={self.ip}')
        try:
            response = requests.get(self.url)
            
            # Check if the request was successful
            if response.status_code == 200:
                soup = bs4(response.text, 'html.parser')
                
                # Find the <tbody> element
                tbody = soup.find('tbody')
                
                if tbody is not None:
                    data = []
                    
                    # Extract data from each row
                    for row in tbody.find_all('tr'):
                        cols = row.find_all('td')
                        row_data = [col.text.strip() for col in cols]
                        data.append(row_data)
                    
                    # Define the column names based on the website's table structure
                    columns = ['First seen (UTC)', 'Last seen (UTC)', 'Category', 'Title', 'Size']
                    
                    # Create a DataFrame
                    df = pd.DataFrame(data, columns=columns)
                    
                    return df
                else:
                    print("No table body found.")
                    return None
            else:
                print(f"Failed to retrieve the webpage: status code {response.status_code}")
                return None
        except Exception as e:
            print(f"An error occurred: {e}")
            return None