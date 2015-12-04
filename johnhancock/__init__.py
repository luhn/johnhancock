import re
import hashlib
import hmac
import binascii
from datetime import datetime as DateTime
from collections import namedtuple


class CanonicalRequest(object):
    """
    An object representing an HTTP request to be made to AWS.

    :param method:  The HTTP method being used.
    :type method:  str
    :param url:  The full URL, including protocol, host, and optionally the
        query string.
    :type uri:  str
    :param query_string:  The URL-encoded query string.  Can be omitted if no
        query string or included in the URL.
    :type query_string:  str
    :param headers:  A dictionary of headers.
    :type headers:  dict
    :param payload:  The request body.
    :type payload:  bytes-like object

    """
    def __init__(
            self,
            method,
            uri,
            query_string=None,
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
    def header_list(self):
        """
        A lowercase list of headers.

        """
        return [
            x.lower() for x in self.headers.keys()
        ]

    @property
    def signed_headers(self):
        return ';'.join(sorted(self.header_list))

    def _set_date_header(self):
        """
        Set the ``X-Amz-Date`` header to the current datetime, if not set.

        :returns:  The datetime from the ``X-Amx-Date`` header.
        :rtype:  :class:`datetime.datetime`

        """
        pass

    def _set_date_param(self):
        """
        Set the ``X-Amz-Date`` query parameter to the current datetime, if not
        set.

        :returns:  The datetime from the ``X-Amx-Date`` parameter.
        :rtype:  :class:`datetime.datetime`

        """
        pass

    def sign_via_headers(self, credentials):
        """
        Create a :clas:`SignedRequest` by adding the appropriate headers.

        :param credentials:  The credentials with which to sign the request.
        :type credentials: :class:`Credentials`

        :returns:  The signed request.
        :rtype:  :class:`SignedRequest`

        """
        pass

    def sign_via_query_string(self, param):
        """
        Create a :clas:`SignedRequest` by adding the appropriate query
        parameters.

        :param credentials:  The credentials with which to sign the request.
        :type credentials: :class:`Client`

        :returns:  The signed request.
        :rtype:  :class:`SignedRequest`

        """
        pass


#: A signed request.  Does not include the request body.
SignedRequest = namedtuple('SignedRequest', [
    'method', 'uri', 'headers',
])


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


class SigningKey(object):
    """
    A signing key from the secret and the credential scope.

    :param secret:  The AWS key secret.
    :type secret:  str
    :param scope:  The credential scope with date.
    :type scope:  :class:`DatedCredentialScope`

    """
    #: The computed signing key as a bytes object
    key = None

    def __init__(self, secret, scope):
        date = scope.date.strftime('%Y%m%d')
        signed_date = self._sign(b'AWS4' + secret.encode('ascii'), date)
        signed_region = self._sign(signed_date, scope.region)
        signed_service = self._sign(signed_region, scope.service)
        self.key = self._sign(signed_service, 'aws4_request')

    def _sign(self, key, value):
        return hmac.new(
            key,
            value.encode('ascii'),
            hashlib.sha256,
        ).digest()

    def sign(self, string):
        """
        Sign a string.  Returns the hexidecimal digest.

        """
        return binascii.hexlify(self._sign(self.key, string)).decode('ascii')


def generate_string_to_sign(date, scope, request):
    """
    Generate a string which should be signed by the signing key.

    :param date:  The datetime of the request.
    :type date:  :class:`datetime.datetime`
    :param scope:  The credential scope.
    :type scope:  :class:`CredentialScope` or :class:`DatedCredentialScope`
    :param request:  The request to sign.
    :type request:  :class:`CanonicalRequest`

    """
    return '\n'.join([
        'AWS4-HMAC-SHA256',
        date.strftime('%Y%m%dT%H:%M:%SZ'),
        date.strftime('%Y%m%d') + '/' + str(scope),
        request.hashed,
    ])


def generate_authorization_header(key, date, scope, request):
    """
    Generate an appropriate value for the authorization header.

    """
    return 'AWS4-HMAC-SHA256 '
    return ' '.join([
        'Credential=' + key.date.strftime('%Y%m%d') + '/' + str(scope),

    ])


class Credentials(object):
    """
    An object that encapsulates all the necessary credentials to sign a
    request.

    """
    def __init__(self, key_id, key_secret, region, service):
        self._key_secret = key_secret
        self._scope = CredentialScope(region, service)

    def scope(self, datetime):
        return self._scope.date(datetime)

    def signing_key(self, datetime):
        return SigningKey(self._key_secret, self.scope(datetime))

    def _auth_header(self, request):
        pass
