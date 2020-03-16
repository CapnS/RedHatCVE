class CVENotFound(Exception):
	"""
	Exception that is thrown when a CVE is not found.
	"""
	def __init__(self, name):
		super().__init__(f"A CVE with the name {name} was not found")
