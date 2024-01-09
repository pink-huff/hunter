from dotenv import load_dotenv
import requests
import os

# Load the .env file
load_dotenv()
api = os.getenv('BLACKLIST_CHECKER_API')

#https://blacklist-checker.readme.io/reference/check-all-blacklists
class BlackListChecker:
    """
    A class to check if a given query is listed in the blacklist using the blacklistchecker.com API.

    Attributes:
        query (str): The query string to be checked against the blacklist.

    Methods:
        check(): Makes an API call to blacklistchecker.com to check if the query is blacklisted.
    """
    def __init__(self, query):
        """
        Initializes the BlackListChecker with a query.

        Parameters:
            query (str): The query string to be checked against the blacklist.
        """
        self.query = query

    def check(self):
        """
        Checks if the provided query is on the blacklist by making an API call to blacklistchecker.com.

        The method performs a GET request to the API with the query. HTTP Basic Authentication is used with
        an API key. The response, if successful (HTTP 200), is returned as a JSON object. In case of failure,
        an error message with the status code or exception details is returned.

        Returns:
            dict: A dictionary with the API response data if the request is successful,
                  or an error message and status code in case of a failure.

        Raises:
            Exception: If there is an issue with the network or other unexpected errors during the API call.
        """
        try:
            # The URL for the API endpoint
            url = f"https://api.blacklistchecker.com/check/{self.query}"

            # Perform the request with HTTP Basic Authentication
            response = requests.get(url, auth=(api, ''))

            # Check if the response was successful
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": "API request failed", "status_code": response.status_code}
        
        except Exception as e:
            return {"error": str(e)}    