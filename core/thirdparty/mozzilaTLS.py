import requests
from urllib.parse import urlparse

MOZILLA_TLS_OBSERVATORY_API = 'https://tls-observatory.services.mozilla.com/api/v1'

class MozillaTLSInfo:
    """
    A class to check if a given URL is listed in the Mozilla TLS Observatory using the Mozilla TLS Observatory API.

    Attributes:
        url (str): The URL to be checked against the Mozilla TLS Observatory.

    Methods:
        check(): Makes an API call to the Mozilla TLS Observatory to check if the URL is listed.
    """
    def __init__(self, url):
        """
        Initializes the MozillaTLS with a URL.

        Parameters:
            url (str): The URL to be checked against the Mozilla TLS Observatory.
        """
        self.url = url

    def check(self):
        """
        Checks if the provided URL is on the Mozilla TLS Observatory by making an API call to the Mozilla TLS Observatory.

        The method performs a POST request to the API with the URL. The response, if successful (HTTP 200), is returned as a JSON object. In case of failure,
        an error message with the status code or exception details is returned.

        Returns:
            dict: A dictionary with the API response data if the request is successful,
                  or an error message and status code in case of a failure.

        Raises:
            Exception: If there is an issue with the network or other unexpected errors during the API call.
        """
        try:
            # The URL for the API endpoint
            url = f"{MOZILLA_TLS_OBSERVATORY_API}/scan?target={self.url}"

            # Perform the request with HTTP Basic Authentication
            response = requests.post(url)

            # Check if the response was successful
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": "API request failed", "status_code": response.status_code}
        
        except Exception as e:
            return {"error": str(e)}