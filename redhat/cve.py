import datetime

class Bugzilla:
	"""
	Default class for a Red Hat's Bugzilla listing.

	Attributes
	------------
	description: :class:`str`
		Description of the bug in Red Hat's Bugzilla.
	id: :class:`str`
		ID of the bug in Red Hat's Bugzilla.
	url: :class:`str`
		URL of the bug in Red Hat's Bugzilla.
	"""
	def __init__(self, data):
		self.description = data['description'].strip()
		self.id = data['id']
		self.url = data ['url']

class CVSSv2:
	"""
	Default class for CVSSv2 metrics of a CVE.

	Attributes
	------------
	base_score: :class:`float`
		CVSSv2 score of the CVE.
	scoring_vector: :class:`str`
		CVSSv2 scoring vector for the CVE.
	status: :class:`str`
		Indicates how far along the investigation of the flaw has progressed.
	"""
	def __init__(self, data):
		self.base_score = float(data['cvss_base_score'])
		self.scoring_vector = data['cvss_scoring_vector']
		self.status = data['status']

class CVSSv3:
	"""
	Default class for CVSSv3 metrics of a CVE.

	Attributes
	------------
	base_score: :class:`float`
		CVSSv3 score of the CVE.
	scoring_vector: :class:`str`
		CVSSv3 scoring vector for the CVE.
	status: :class:`str`
		Indicates how far along the investigation of the flaw has progressed.
	"""
	def __init__(self, data):
		self.base_score = float(data['cvss3_base_score'])
		self.scoring_vector = data['cvss3_scoring_vector']
		self.status = data['status']

class Release:
	"""
	Default class for a package release.

	Attributes
	------------
	product_name: :class:`str`
		Name of the product the package is for.
	release_date: :class:`str`
		Release date of the package (ISO 8601 format).
	advisory: :class:`str`
		Package advisory.
	cpe: :class:`str`
		CPE string for the package.
	package_name: Optional[:class:`str`]
		Name of the package that fixes the flaw.
	"""
	def __init__(self, data):
		self.product_name = data['product_name']
		self.release_date = data['release_date']
		self.advisory = data['advisory']
		self.cpe = data['cpe']
		self.package_name = data.get('package_name', None)

class PackageState:
	"""
	Default class for a package state for a package that hasn't been fixed yet

	Attributes
	------------
	product_name: :class:`str`
		Name of the product which uses the package.
	fix_state: :class:`str`
		State of fixing, can be one of these values: 'Affected', 'Fix deferred', 'New', 'Not affected', or 'Will not fix'.
	package_name: :class:`str`
		Name of the package that hasn't been fixed.
	cpe: :class:`str`
		CPE string for the package. 
	"""
	def __init__(self, data):
		self.product_name = data['product_name']
		self.fix_state = data['fix_state']
		self.package_name = data['package_name']
		self.cpe = data['cpe']

class CVE:
	"""
	The default class for a CVE.

	Attributes
	------------
	name: :class:`str`
		The CVE name.
	threat_severity: :class:`str`
		The severity of the flaw.
	public_date: :class:`str`
		When the flaw became public (ISO 8601 format).
	bugzilla: :class:`~redhat.Bugzilla`
		Redhat Bugzilla listing for this CVE.
	cvss: :class:`~redhat.CVSS`
		CVSSv2 score and metrics for this CVE.
	cwe: :class:`str`
		The CWE chain for this flaw (See the mitre.org description (https://cwe.mitre.org/about/index.html) and the list of possible cwe values (https://access.redhat.com/articles/171613).)
	details: List[:class:`str`]
		Details about the flaw, possibly from Red Hat or Mitre.
	statement: Optional[:class:`str`]
		A statement from Red Hat about the issue.
	affected_releases: Optional[List[:class:`~redhat.Release`]]
		A released Erratum that fixes the flaw for a particular product.
	package_states: List[:class:`~redhat.PackageState`]
		Information about a package / product where no fix has been released yet.

	NOT ADDED YET(DON'T KNOW FORMATTING)
	references: 
		Links to more information about the issue.
	acknowledgements:
		People or organizations that are being recognized.
	mitigation:
		A way to fix or reduce the problem without updated software.
	upstream_fix:
		The version of the upstream project that fixes the flaw.
	"""
	def __init__(self, data, passthrough=None):
		self.passthrough = passthrough
		if self.passthrough:
			return
		self.name = data['name']
		self.threat_severity = data.get('threat_severity', None)
		self.public_date = data.get('public_date', None)
		self.bugzilla = Bugzilla(data['bugzilla']) if data.get('bugzilla') else None
		try:
			self.cvss = CVSSv2(data['cvss'])
		except KeyError:
			self.cvss = CVSSv3(data['cvss3']) if data.get('cvss3') else None
		self.cwe = data.get('cwe', None)
		self.details = ' '.join([detail.strip() for detail in data['details']])
		self.statement = data.get('statement', None)
		self.affected_releases = [Release(release) for release in data['affected_release']] if data.get('affected_release') else []
		self.package_states = [PackageState(package_state) for package_state in data['package_state']] if data.get('package_state') else []
		self.in_fork = False

		# self.references = data.get('references', None)
		# self.acknowledgements = data.get('acknowledgements', None)
		# self.mitigation = data.get('mitigation', None)
		# self.upstream_fix = data.get('upstream_fix', None)

	def to_dict(self):
		if self.passthrough:
			output = {
				'CVE ID': self.passthrough,
				'Headline': None,
				'CVSS Score': None,
				'RH Impact': None,
				'RHEL 7': None,
				'RHEL 7.6 EUS': None,
				'RHEL 8': None,
				'Notes': 'A CVE with this ID was not found on the Redhat Database.'
			}
			return output
		output = {
			'CVE ID': self.name,
			'Headline': self.details,
			'CVSS Score': self.cvss.base_score if self.cvss else None,
			'RH Impact': self.threat_severity,
		}
		all_states = {}
		for state in self.package_states:
			all_states[state.product_name.replace('Red Hat Enterprise Linux', 'RHEL').replace('Extended Update Support', 'EUS')] = state.fix_state
		for release in self.affected_releases:
			pname = release.product_name.replace('Red Hat Enterprise Linux', 'RHEL').replace('Extended Update Support', 'EUS')
			all_states[pname] = 'Fixed'
			if pname == 'RHEL 7':
				date = datetime.datetime.strptime(release.release_date[:10], '%Y-%m-%d')
				if date <= datetime.datetime.strptime('2019-08-05', '%Y-%m-%d'):
					self.in_fork = True
		for package in ['RHEL 7.6 EUS', 'RHEL 7', 'RHEL 8']:
			if package in all_states:
				output[package] = all_states[package]
			elif all_states.get('RHEL 5') == 'Fixed' or all_states.get('RHEL 6') == 'Fixed':
				output[package] = 'Not Affected'
			elif package == 'RHEL 7.6 EUS' and self.in_fork:
				output[package] = 'Fixed'
			elif package == 'RHEL 8' and 'RHEL 7' in all_states:
				output[package] = all_states['RHEL 7']
			else:
				if self.threat_severity in ('high', 'critical'):
					output[package] = 'TBD'
				else:
					output[package] = 'Assume WNF'
		output['Notes'] = ''
		return output