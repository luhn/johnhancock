import pytest
import textwrap
from datetime import datetime as DateTime

from johnhancock import CanonicalRequest, Headers


def test_canon_request_init():
    canon_request = CanonicalRequest(
        'GET',
        'https://aws.amazon.com/foo',
        [
            ('Action', 'ListUsers'),
            ('Version', '2010-05-08'),
        ],
        {
            'Host': 'example.com',
            'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
            'X-Amz-Date': '20150830T123600Z',
        },
    )
    assert canon_request.method == 'GET'
    assert canon_request._parts == (
        'https',
        'aws.amazon.com',
        '/foo',
        '',
        '',
    )
    assert canon_request.query == [
        ('Action', 'ListUsers'),
        ('Version', '2010-05-08'),
    ]
    assert canon_request.headers == Headers({
        'Host': 'example.com',
        'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
        'X-Amz-Date': '20150830T123600Z',
    })


def test_canon_request_init_implicit_host():
    canon_request = CanonicalRequest(
        'GET',
        'https://aws.amazon.com/foo',
        headers={
            'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
            'X-Amz-Date': '20150830T123600Z',
        },
    )
    assert canon_request.headers == Headers({
        'Host': 'aws.amazon.com',
        'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
        'X-Amz-Date': '20150830T123600Z',
    })


def test_canon_request_init_query_types():
    canon_request = CanonicalRequest(
        'GET',
        'https://aws.amazon.com/foo',
        {
            'Action': 'ListUsers',
            'Version': '2010-05-08',
        },
    )
    assert set(canon_request.query) == {
        ('Action', 'ListUsers'),
        ('Version', '2010-05-08'),
    }

    canon_request = CanonicalRequest(
        'GET',
        'https://aws.amazon.com/foo',
        'Action=ListUsers&Version=2010-05-08',
    )
    assert canon_request.query == [
        ('Action', 'ListUsers'),
        ('Version', '2010-05-08'),
    ]


def test_canon_request_payload():
    canon_request = CanonicalRequest(
        'GET',
        '/',
        'Action=ListUsers&Version=2010-05-08',
        payload=b'foo',
    )
    with pytest.raises(NotImplementedError):
        canon_request.payload

    assert (
        canon_request.hashed_payload ==
        '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae'
    )

    canon_request.payload = b''
    assert (
        canon_request.hashed_payload ==
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    )

    # String input shouldn't be accepted.
    with pytest.raises(TypeError):
        canon_request.payload = u''


def test_headers_object():
    h = Headers({
        'Foo': 'Bar',
        'fizz': 'buzz',
    })
    h['Baz'] = 'Fuzz'
    assert h['bAz'] == 'Fuzz'
    assert len(h) == 3
    assert {k for k in h} == set(h.keys()) == {'foo', 'baz', 'fizz'}
    del h['fIzz']
    assert set(h.keys()) == {'foo', 'baz'}


def test_canon_request_headers():
    canon_request = CanonicalRequest(
        'GET',
        '/',
        headers={
            'Host': 'iam.amazonaws.com',
            'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
            'X-Amz-Date': '20150830T123600Z',
            'My-header1': '   a   b   c ',
            'My-Header2': '"a   b   c"',
        },
    )
    # Case insensitive keys
    assert canon_request.headers['x-aMZ-daTe'] == '20150830T123600Z'
    assert set(canon_request.headers.keys()) == {
        'content-type', 'host', 'my-header1', 'my-header2', 'x-amz-date',
    }
    canon_request.headers['Testing'] = 'foo'
    assert canon_request.headers['tEsting'] == 'foo'


def test_canon_request_canon_headers():
    canon_request = CanonicalRequest(
        'GET',
        '/',
        headers={
            'Host': 'iam.amazonaws.com',
            'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
            'X-Amz-Date': '20150830T123600Z',
            'My-header1': '   a   b   c ',
            'My-Header2': '"a   b   c"',
        },
    )
    assert canon_request.canonical_headers == (
        'content-type:application/x-www-form-urlencoded; charset=utf-8\n'
        + 'host:iam.amazonaws.com\n'
        + 'my-header1:a b c\n'
        + 'my-header2:"a   b   c"\n'
        + 'x-amz-date:20150830T123600Z\n'
    )
    assert (
        canon_request.signed_headers ==
        'content-type;host;my-header1;my-header2;x-amz-date'
    )


def test_canon_request_str():
    canon_request = CanonicalRequest(
        'GET',
        '/',
        'Action=ListUsers&Version=2010-05-08',
        {
            'Host': 'iam.amazonaws.com',
            'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
            'X-Amz-Date': '20150830T123600Z',
        },
    )
    assert str(canon_request) == (
        'GET\n'
        + '/\n'
        + 'Action=ListUsers&Version=2010-05-08\n'
        + 'content-type:application/x-www-form-urlencoded; charset=utf-8\n'
        + 'host:iam.amazonaws.com\n'
        + 'x-amz-date:20150830T123600Z\n\n'
        + 'content-type;host;x-amz-date\n'
        + 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    )


def test_canon_request_hashed():
    canon_request = CanonicalRequest(
        'GET',
        '/',
        'Action=ListUsers&Version=2010-05-08',
        {
            'Host': 'iam.amazonaws.com',
            'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
            'X-Amz-Date': '20150830T123600Z',
        },
    )
    assert (
        canon_request.hashed ==
        'f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59'
    )


def test_canon_request_set_date_header():
    canon_request = CanonicalRequest(
        'GET',
        '/',
        'Action=ListUsers&Version=2010-05-08',
        {
            'Host': 'iam.amazonaws.com',
            'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
        },
    )
    canon_request._datetime = lambda: DateTime(2015, 8, 30, 12, 37)
    canon_request._set_date_header()
    assert canon_request.headers['x-amz-date'] == '20150830T123700Z'


def test_canon_request_set_date_header_already_exists():
    canon_request = CanonicalRequest(
        'GET',
        '/',
        'Action=ListUsers&Version=2010-05-08',
        {
            'Host': 'iam.amazonaws.com',
            'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
            'X-Amz-Date': '20150830T123600Z',
        },
    )
    canon_request._set_date_header()
    assert canon_request.headers['X-Amz-Date'] == '20150830T123600Z'
