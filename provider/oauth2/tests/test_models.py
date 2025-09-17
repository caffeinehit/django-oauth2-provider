
from django.test import TestCase

from provider.oauth2.models import Client, AwsAccount


class ModelTests(TestCase):
    fixtures = ['test_oauth2']

    def test_aws_account(self):
        client = Client.objects.get(id=2)

        account = AwsAccount.objects.create(
            client=client,
            arn="arn:aws:iam::123456789012:user/imauser"
        )

        self.assertEqual(account.account_id, "123456789012")
        self.assertEqual(account.name, "imauser")
        self.assertEqual(account.general_type, "user")

        new_account = AwsAccount.objects.get(pk=account.pk)

        self.assertEqual(new_account.account_id, "123456789012")
        self.assertEqual(new_account.name, "imauser")
        self.assertEqual(new_account.general_type, "user")
