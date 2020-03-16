import requests

class HTTPClient:
	"""Represents an HTTP client sending HTTP requests to the Red Hat CVE API."""
	
	def __init__(self):
		self.BASE = 'https://access.redhat.com/hydra/rest/securitydata'

	def fetch_cve(self, name):
		with requests.get(f'{self.BASE}/cve/{name}.json') as response:
			return response.json()
		
