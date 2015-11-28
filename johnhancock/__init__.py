import re
import hashlib
import hmac
from collections import namedtuple


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


class CredentialScope(
        namedtuple('CredentialScope', ['region', 'service'])
):
    """
    The credential scope, sans date.

    :param region:  The region the request is querying.  See
        `Regions and Endpoints`_ for a list of values.
    :type region:  str
    :param service:  The service the request is querying.
    :type service:  str

    """
    def date(self, date):
        """
        Generate a :class:`DatedCredentialScope` from this objec.t

        """
        return DatedCredentialScope(
            self.region,
            self.service,
            date,
        )


class DatedCredentialScope(
        namedtuple('DatedCredentialScope', ['region', 'service', 'date'])
):
    """
    The credential scope, generated from the region and service.

    :param region:  The region the request is querying.  See
        `Regions and Endpoints`_ for a list of values.
    :type region:  str
    :param service:  The service the request is querying.
    :type service:  str
    :param date:  The date for the credential scope.
    :type date:  :class:`datetime.date` or :class:`datetime.datetime`

    .. _`Regions and Endpoints`:
        http://docs.aws.amazon.com/general/latest/gr/rande.html

    """
    def __str__(self):
        """
        Calculate the credential scope for the given date.


        """
        return '/'.join([
            self.date.strftime('%Y%m%d'),
            self.region,
            self.service,
            'aws4_request',
        ])


def generate_signing_key(secret, scope):
    """
    Generate a signing key from the secret and the credential scope.

    :param secret:  The AWS key secret.
    :type secret:  str
    :param scope:  The credential scope with date.
    :type scope:  :class:`DatedCredentialScope`

    :returns:  The signing key.
    :rtype:  bytes

    """
    def sign(key, value):
        return hmac.new(key, value.encode('ascii'), hashlib.sha256).digest()
    date = scope.date.strftime('%Y%m%d')
    signed_date = sign(b'AWS4' + secret.encode('ascii'), date)
    signed_region = sign(signed_date, scope.region)
    signed_service = sign(signed_region, scope.service)
    return sign(signed_service, 'aws4_request')
