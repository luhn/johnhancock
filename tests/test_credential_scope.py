from datetime import datetime as DateTime, date as Date

from johnhancock import CredentialScope


def test_credential_scope():
    cred_scope = CredentialScope('us-east-1', 'iam')
    assert (
        cred_scope.calculate(Date(2013, 6, 27)) ==
        '20130627/us-east-1/iam/aws4_request'
    )
    assert (
        cred_scope.calculate(DateTime(2013, 6, 27, 13, 15)) ==
        '20130627/us-east-1/iam/aws4_request'
    )
