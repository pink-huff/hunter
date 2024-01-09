import requests
import datetime
from urllib.parse import urlparse
import json
from bs4 import BeautifulSoup
from core.general.errorresponse import error_response

class GDELT:
    def details(self):
        """
        Provides details about the GDELT source.

        Returns:
        dict: A dictionary containing details such as source name, title, color, description, and available methods.
        """
        return {
            'source': "gdelt",
            'title': "GDELT",
            'color': "#698F3F",
            'description': "News Aggregation",
            'method': ["locationSearch", "documentSearch"]
        }

    def call(self, query):
        """
        Processes a query to the GDELT API.

        Args:
        query (dict): A dictionary containing query parameters and values.

        Returns:
        dict: A dictionary containing the response from the GDELT API, including error messages, results, and query status.
        """
        response = {
            'error': {
                'error': False
            },
            'holding': {
                'loop': 0,
                'previousCount': -1,
            },
            'result': []
        }

        if 'method' not in query:
            response['error']['error'] = True
            response['error']['message'] = "Invalid method passed"
            return response

        if query['method'] == "locationSearch":
            if 'geo' not in query or 'lat' not in query['geo'] or 'lon' not in query['geo'] or 'rad' not in query['geo']:
                response['error']['error'] = True
                response['error']['message'] = "Invalid geo sent"
                return response
            else:
                query['text'] = f"near:{query['geo']['lat']},{query['geo']['lon']},{query['geo']['rad']}km"
                response = self.call_geo(query, response)

        elif query['method'] == "documentSearch":
            if 'text' not in query or not isinstance(query['text'], str):
                response['error']['error'] = True
                response['error']['message'] = "Invalid text sent"
                return response
            else:
                response = self.call_document(query, response)

        else:
            response['error']['error'] = True
            response['error']['message'] = "Invalid method passed"

        return response

    def call_geo(self, query, response):
        """
        Processes a geographic query to the GDELT API.

        Args:
        query (dict): A dictionary containing geographic query parameters.
        response (dict): The initial response dictionary to be updated with the results.

        Returns:
        dict: An updated response dictionary with the results from the geographic query.
        """
        try:
            url = "https://api.gdeltproject.org/api/v2/geo/geo"
            payload = {
                'query': query['text'],
                'format': "geoJSON"
            }

            result = requests.get(url, params=payload)

            if result.status_code == 200:
                data = result.json()

                for feature in data['features']:
                    soup = BeautifulSoup(feature['properties']['html'], 'html.parser')
                    for a in soup.find_all('a', href=True):
                        response['result'].append({
                            'source': {
                                'name': "gdelt",
                                'link': a['href'],
                                'search_time': int(datetime.datetime.now().timestamp()),
                                'type': "news"
                            },
                            'post': {
                                'id': ''.join(e for e in a['href'] if e.isalnum()),
                                'text': a.get('title'),
                                'geo_tag': {
                                    'object': json.dumps(feature['geometry']),
                                    'co_ord': feature['geometry']['coordinates'],
                                    'name': feature['properties']['name']
                                }
                            },
                            'author': {
                                'screen_name': urlparse(a['href']).hostname,
                            }
                        })
            else:
                response['error']['error'] = True
                response['error']['message'] = "Unable to get geo results"
        except Exception as e:
            response['error']['error'] = True
            response['error']['message'] = str(e)

        return response

    def call_document(self, query, response):
        """
        Processes a document search query to the GDELT API.

        Args:
        query (dict): A dictionary containing document search query parameters.
        response (dict): The initial response dictionary to be updated with the results.

        Returns:
        dict: An updated response dictionary with the results from the document search query.
        """
        try:
            url = "https://api.gdeltproject.org/api/v2/doc/doc"
            payload = {
                'format': "JSON",
                'mode': "ArtList",
                'maxrecords': 50,
                'sort': "DateDesc",
                'timespan': "1w",
                'query': query['text']
            }

            result = requests.get(url, params=payload)

            if result.status_code == 200:
                data = result.json()

                for article in data['articles']:
                    response['result'].append({
                        'source': {
                            'name': "Gdelt",
                            'link': article['url'],
                            'type': "news",
                            'search_time': int(datetime.datetime.now().timestamp())
                        },
                        'post': {
                            'id': ''.join(e for e in article['url'] if e.isalnum()),
                            'text': article['title'],
                            'language': article['language'],
                            'created_at': int(datetime.datetime.strptime(article['seendate'], "%Y%m%dT%H%M%SZ").timestamp())#int(datetime.datetime.strptime(article['seendate'], "%Y%m%d%H%M%S").timestamp())
                            
                        },
                        'author': {
                            'screen_name': article['domain'],
                            'location': article['sourcecountry']
                        }
                    })
            else:
                response['error']['error'] = True
                response['error']['message'] = "Unable to get document results"
        except Exception as e:
            response['error']['error'] = True
            response['error']['message'] = str(e)

        return response
