"""
Test cases for functionality provided by the provider.utils module
"""

from django.test import TestCase

from provider.utils import ArnHelper, BadArn


class UtilsTestCase(TestCase):
    def test_arn_user_helper(self):
        user_arn = "arn:aws:iam::123456789012:user/imauser"

        arn = ArnHelper(user_arn)
        self.assertEqual(arn.account_id, "123456789012")
        self.assertEqual(arn.type, "user")
        self.assertEqual(arn.name, "imauser")

    def test_arn_user_equality(self):
        user_arn = "arn:aws:iam::123456789012:user/imauser"

        arn = ArnHelper(user_arn)

        caller_identity_arn = ArnHelper("arn:aws:iam::123456789012:user/imauser")

        self.assertEqual(arn, caller_identity_arn)

    def test_arn_role_helper(self):
        role_arn = "arn:aws:iam::123456789012:role/my-ec2-role"
        arn = ArnHelper(role_arn)

        self.assertEqual(arn.account_id, "123456789012")
        self.assertEqual(arn.type, "role")
        self.assertEqual(arn.name, "my-ec2-role")

    def test_arn_role_caller_identity_helper(self):
        role_arn = "arn:aws:sts::123456789012:assumed-role/my-ec2-role/sessionidentifier"
        arn = ArnHelper(role_arn)
        self.assertEqual(arn.account_id, "123456789012")
        self.assertEqual(arn.type, "assumed-role")
        self.assertEqual(arn.general_type, "role")
        self.assertEqual(arn.name, "my-ec2-role")
        self.assertEqual(arn.session, "sessionidentifier")

    def test_arn_role_equality(self):
        role_arn = "arn:aws:iam::123456789012:role/my-ec2-role"
        arn = ArnHelper(role_arn)

        caller_identity_arn = ArnHelper(
            "arn:aws:sts::123456789012:assumed-role/my-ec2-role/sessionidentifier"
        )

        self.assertEqual(arn, caller_identity_arn)

    def test_invalid_arn_too_long(self):
        with self.assertRaises(BadArn):
            ArnHelper("arn:aws:iam::123456789012:role/my-ec2-role:invalidextra")

    def test_invalid_arn_too_short(self):
        with self.assertRaises(BadArn):
            ArnHelper("arn:aws:iam::123456789012")

    def test_invalid_arn_bad_prefix(self):
        with self.assertRaises(BadArn):
            ArnHelper("notarn:aws:iam::123456789012:role/my-ec2-role")

    def test_invalid_arn_bad_service(self):
        with self.assertRaises(BadArn):
            ArnHelper("arn:aws:s3::123456789012:role/my-ec2-role")
