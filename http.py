import requests

class HTTPClient:
    """Represents an HTTP client sending HTTP requests to the Red Hat CVE API."""
    
    BASE = 'https://access.redhat.com/hydra/rest/securitydata'

    def request(self, method, path, **parameters):
        url = self.BASE + path
        with requests.request(method, url, json=parameters) as response:
            return response.json()

    def fetch_cve(self, name):
        return self.request('GET', f'/cve/CVE-{name}.json')
