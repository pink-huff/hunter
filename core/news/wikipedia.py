import requests

class WikipediaAPI:
    """
    A class for interacting with Wikipedia's API to search for articles and retrieve their summaries.
    """
    base_url = "https://en.wikipedia.org/w/api.php"

    def __init__(self):
        """
        Initializes the WikipediaAPI class.
        """
        pass

    def search_article(self, query):
        """
        Searches for articles on Wikipedia matching the given query.

        Args:
        query (str): The search query.

        Returns:
        list: A list of search results, or None if an error occurs.
        """
        params = {
            "action": "query",
            "format": "json",
            "list": "search",
            "srsearch": query
        }

        try:
            response = requests.get(self.base_url, params=params)
            response.raise_for_status()
            data = response.json()
            return data['query']['search']
        except requests.exceptions.RequestException as e:
            print("Error occurred while making the request:", e)
            return None

    def get_summary(self, query):
        """
        Retrieves a summary of the first search result for a given query.

        Args:
        query (str): The search query.

        Returns:
        str: A summary of the first search result, an error message if no summary is found, or if no search results are found.
        """
        search_results = self.search_article(query)

        if search_results:
            first_article_title = search_results[0]['title']
            summary = self.retrieve_summary(first_article_title)
            if summary:
                return summary
            else:
                return "Summary not found for the article."
        else:
            return "No search results found."

    def retrieve_summary(self, page_title):
        """
        Retrieves a summary for a given Wikipedia page title.

        Args:
        page_title (str): The title of the Wikipedia page.

        Returns:
        str or None: A summary of the specified page, None if an error occurs or if the page doesn't have a summary.
        """
        params = {
            "action": "query",
            "format": "json",
            "prop": "extracts",
            "exintro": True,
            "titles": page_title
        }

        try:
            response = requests.get(self.base_url, params=params)
            response.raise_for_status()
            data = response.json()
            page_id = next(iter(data['query']['pages'].keys()))
            summary = data['query']['pages'][page_id]['extract']
            if summary:
                return summary
            else:
                return None
        except requests.exceptions.RequestException as e:
            print("Error occurred while making the request:", e)
            return None
        except KeyError:
            print("Invalid response format received from Wikipedia API.")
            return None
