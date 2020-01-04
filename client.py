from .http import HTTPClient
from .cve import CVE
from .errors import CVENotFound

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
            Either a list of the CVE names to search for or a single CVE name
        
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
