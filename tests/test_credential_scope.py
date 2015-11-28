from datetime import datetime as DateTime, date as Date

from johnhancock import CredentialScope, DatedCredentialScope


def test_cred_scope_date():
    cred_scope = CredentialScope('us-east-1', 'iam')
    assert (
        cred_scope.date(Date(2013, 6, 27)) ==
        DatedCredentialScope('us-east-1', 'iam', Date(2013, 6, 27))
    )


def test_cred_scope_string():
    cred_scope = DatedCredentialScope('us-east-1', 'iam', Date(2013, 6, 27))
    assert str(cred_scope) == '20130627/us-east-1/iam/aws4_request'

    cred_scope = DatedCredentialScope(
        'us-east-1',
        'iam',
        DateTime(2013, 6, 27, 13, 15),
    )
    assert str(cred_scope) == '20130627/us-east-1/iam/aws4_request'
