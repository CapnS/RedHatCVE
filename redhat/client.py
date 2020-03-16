from .http import HTTPClient
from .cve import CVE
from .errors import CVENotFound
import pandas
import time 

class Client:
	"""
	Base client used for interacting with the Red Hat CVE API.
	"""
	def __init__(self):
		self.http = HTTPClient()

	def fetch_cve(self, *names):
		"""
		Fetches a single or a list of CVE's with the name given.

		Parameters
		------------
		names: Union[List[:class:`str`], :class:`str`]
			Either a list of the CVE names to search for or a single CVE name.
		
		Raises
		------------
		~redhat.NotFound
			A CVE with the name passed was not found.

		Returns
		------------
		Union[List[:class:`~redhat.CVE`], :class:`~redhat.CVE`]
			Either a list of the CVEs or the CVE with the passed name(s).
		"""
		try:
			if len(names) > 1:
				output = []
				for name in names:
					output.append(CVE(self.http.fetch_cve(name)))
				return output
			else:
				name = names[0]
				return CVE(self.http.fetch_cve(name))
		except KeyError:
			raise CVENotFound(name)

	def fetch_from_csv(self, filename, column='CVE', output_filename=None):
		"""
		Fetches all CVEs from the .csv file passed.

		Parameters
		------------
		filename: :class:`str`
			Name of the file (.csv) to read input data from.
		column: :class:`str`
			Name of the column in which CVEs are listed in the input file. Defaults to 'CVE'.
		output_filename: Optional[:class:`str`]
			Filename (.csv) to write the output to. If left None, will leave output as list of :class:`~redhat.CVE`. Defaults to None.
		
		Raises
		------------
		~redhat.NotFound
			A CVE with the name passed was not found.
		~FileNotFoundError
			The input file (.csv) was not found. 

		Returns
		------------
		Union[List[:class:`~redhat.CVE`], :class:`pandas.DataFrame`]
			Either a list of the CVEs or the DataFrame that was written if set to output as csv.
		"""
		t = time.perf_counter()
		df = pandas.read_csv(filename)
		output = []
		for i, name in enumerate(df[column]):
			data = self.http.fetch_cve(name)
			if data.get('message'):
				print(name, data['message'])
			else:
				output.append(CVE(data))
			if not (i + 1) % 25:
				print(f'{i+1} CVEs done, {round(time.perf_counter() - t, 2)} seconds passed')
		if not output_filename:
			print(f'Finished Parsing, {round(time.perf_counter() - t, 2)} seconds passed')
			return output
		else:
			print(f'Finished Parsing, {round(time.perf_counter() - t, 2)} seconds passed. Writing data to {output_filename} file now.')
			return self.to_csv(output, output_filename, t)

	def to_csv(self, cves, output_filename, t):
		output = [cve.to_dict() for cve in cves]
		df = pandas.DataFrame(output)
		df.to_csv(output_filename)
		print(f'Finished writing data. Total Time Passed: {round(time.perf_counter() - t, 2)} seconds.')
		return df
