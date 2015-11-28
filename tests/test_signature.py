from datetime import date as Date

from johnhancock import generate_signing_key, DatedCredentialScope


def test_signing_key():
    scope = DatedCredentialScope(
        'us-east-1',
        'iam',
        Date(2015, 8, 30),
    )
    key = generate_signing_key(
        'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
        scope,
    )
    assert key == bytearray([
        196, 175, 177, 204, 87, 113, 216, 113, 118, 58, 57, 62, 68, 183, 3, 87,
        27, 85, 204, 40, 66, 77, 26, 94, 134, 218, 110, 211, 193, 84, 164, 185,
    ])
