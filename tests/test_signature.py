from datetime import date as Date

from johnhancock import SigningKey, DatedCredentialScope


def test_signing_key():
    scope = DatedCredentialScope(
        'us-east-1',
        'iam',
        Date(2015, 8, 30),
    )
    signing_key = SigningKey(
        'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
        scope,
    )
    assert signing_key.key == bytearray([
        196, 175, 177, 204, 87, 113, 216, 113, 118, 58, 57, 62, 68, 183, 3, 87,
        27, 85, 204, 40, 66, 77, 26, 94, 134, 218, 110, 211, 193, 84, 164, 185,
    ])


def test_signing_key_sign():
    scope = DatedCredentialScope(
        'us-east-1',
        'iam',
        Date(2015, 8, 30),
    )
    signing_key = SigningKey(
        'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
        scope,
    )
    string = (
        'AWS4-HMAC-SHA256\n'
        + '20150830T123600Z\n'
        + '20150830/us-east-1/iam/aws4_request\n'
        + 'f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59'
    )
    assert (
        signing_key.sign(string) ==
        '5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7'
    )
