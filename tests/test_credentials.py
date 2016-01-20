from datetime import datetime as DateTime, date as Date
from johnhancock import (
    Credentials, CredentialScope, CanonicalRequest, DatedCredentialScope,
    SigningKey,
)


def test_credentials_basic():
    c = Credentials('id', 'secret', 'us-west-2', 'sqs')

    assert c._scope == CredentialScope('us-west-2', 'sqs')

    dt = DateTime(2015, 8, 30, 12, 15)
    assert c.scope(dt) == DatedCredentialScope('us-west-2', 'sqs', dt)

    assert (
        c.signing_key(dt).sign('')
        == SigningKey('secret', c.scope(dt)).sign('')
    )


def test_credentials_sign_via_headers():
    c = Credentials(
        'AKIDEXAMPLE',
        'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
        'us-east-1',
        'iam',
    )
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
    headers = c.sign_via_headers(canon_request)
    assert len(headers) == 1
    assert headers[0] == ('Authorization', (
        'AWS4-HMAC-SHA256 '
        + 'Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, '
        + 'SignedHeaders=content-type;host;x-amz-date, '
        + 'Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a'
        + '6f2b5d7'
    ))


def test_credentials_sign_via_headers_add_date():
    c = Credentials(
        'AKIDEXAMPLE',
        'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
        'us-east-1',
        'iam',
    )
    canon_request = CanonicalRequest(
        'GET',
        '/',
        'Action=ListUsers&Version=2010-05-08',
        {
            'Host': 'iam.amazonaws.com',
            'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
        },
    )
    canon_request._datetime = lambda: DateTime(2015, 8, 30, 12, 36)
    headers = c.sign_via_headers(canon_request)
    assert len(headers) == 2
    assert headers[0] == ('X-Amz-Date', '20150830T123600Z')
    assert headers[1] == ('Authorization', (
        'AWS4-HMAC-SHA256 '
        + 'Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, '
        + 'SignedHeaders=content-type;host;x-amz-date, '
        + 'Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a'
        + '6f2b5d7'
    ))


def test_credentials_sign_via_params():
    c = Credentials(
        'AKIDEXAMPLE',
        'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
        'us-east-1',
        'iam',
    )
    canon_request = CanonicalRequest(
        'GET',
        '/',
        'Action=ListUsers&Version=2010-05-08',
        {
            'Host': 'iam.amazonaws.com',
            'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
        },
    )
    canon_request._datetime = lambda: DateTime(2015, 8, 30, 12, 36)
    params = c.sign_via_query_string(canon_request)
    assert len(params) == 6
    assert params[0] == ('X-Amz-Algorithm', 'AWS4-HMAC-SHA256')
    assert params[1] == (
        'X-Amz-Credential', 'AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request',
    )
    assert params[2] == ('X-Amz-Date', '20150830T123600Z')
    assert params[3] == ('X-Amz-Expires', '60')
    assert params[4] == ('X-Amz-SignedHeaders', 'content-type;host')
    assert params[5] == (
        'X-Amz-Signature',
        '37ac2f4fde00b0ac9bd9eadeb459b1bbee224158d66e7ae5fcadb70b2d181d02',
    )
