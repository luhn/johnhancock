import re
import hashlib


class CanonicalRequest(object):
    """
    An object representing an HTTP request to be made to AWS.

    :param method:  The HTTP method being used.
    :type method:  str
    :param uri:  The URL path, no host or query string.
    :type uri:  str
    :param query_string:  The URL-encoded query string.
    :type query_string:  str
    :param headers:  A dictionary of headers.
    :type headers:  dict
    :param payload:  The request body.
    :type payload:  bytes-like object

    """
    def __init__(
            self,
            method,
            uri='/',
            query_string='',
            headers={},
            payload=b'',
    ):
        self.method = method
        self.uri = uri
        self.query_string = query_string
        self.headers = headers
        self.payload = payload

    def __str__(self):
        return '\n'.join([
            self.method,
            self.uri,
            self.query_string,
            self.canonical_headers,
            self.signed_headers,
            self.hashed_payload,
        ])

    @property
    def hashed(self):
        return hashlib.sha256(str(self).encode('ascii')).hexdigest()

    @property
    def payload(self):
        raise NotImplementedError('Cannot directly access payload.')

    @payload.setter
    def payload(self, value):
        self.hashed_payload = hashlib.sha256(value).hexdigest()

    @property
    def canonical_headers(self):
        lines = []
        for header, value in sorted(
                self.headers.items(),
                key=lambda x: x[0].lower(),
        ):
            value = value.strip()
            # Eliminate duplicate spaces in non-quoted headers
            if not (len(value) >= 2 and value[0] == '"' and value[-1] == '"'):
                value = re.sub(r' +', ' ', value)
            lines.append('{}:{}'.format(header.lower(), value))
        return '\n'.join(lines) + '\n'

    @property
    def signed_headers(self):
        return ';'.join(sorted(
            x.lower() for x in self.headers.keys()
        ))


class CredentialScope(object):
    """
    The credential scope, generated from the region and service.

    :param region:  The region the request is querying.  See
        `Regions and Endpoints`_ for a list of values.
    :type region:  str
    :param service:  The service the request is querying.
    :type service:  str

    .. _`Regions and Endpoints`:
        http://docs.aws.amazon.com/general/latest/gr/rande.html

    """
    def __init__(self, region, service):
        self.region = region
        self.service = service

    def calculate(self, date):
        """
        Calculate the credential scope for the given date.

        :param date:  The date for the credential scope.
        :type date:  :class:`datetime.date` or :class:`datetime.datetime`

        """
        return '/'.join([
            date.strftime('%Y%m%d'),
            self.region,
            self.service,
            'aws4_request',
        ])
