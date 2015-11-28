import pytest
import textwrap

from johnhancock import CanonicalRequest


def test_canon_request_basics():
    canon_request = CanonicalRequest(
        'GET',
        '/',
        'Action=ListUsers&Version=2010-05-08',
        {
            'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
            'X-Amz-Date': '20150830T123600Z',
        },
    )
    assert canon_request.method == 'GET'
    assert canon_request.uri == '/'
    assert canon_request.query_string == 'Action=ListUsers&Version=2010-05-08'
    assert canon_request.headers == {
        'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
        'X-Amz-Date': '20150830T123600Z',
    }


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