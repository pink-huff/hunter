from dotenv import load_dotenv
import requests
import json
import os

# Load the .env file
load_dotenv()
api = os.getenv('VIRUS_TOTAL_API')

# URL to scan
def scan_url():
    url = "https://www.virustotal.com/api/v3/urls"

    payload = { "url": "https://cnn.com" }
    headers = {
        "accept": "application/json",
        "x-apikey": f"{api}",
        "content-type": "application/x-www-form-urlencoded"
    }


    response = requests.post(url, data=payload, headers=headers)

    return response.text

print(scan_url())