from django.contrib.auth.models import User
from django.db.models.signals import pre_save
from django.dispatch import receiver

from provider.utils import ArnHelper
from provider.oauth2.models import AwsAccount


@receiver(pre_save, sender=AwsAccount)
def awsaccount_pre_save(sender, instance, **kwargs):
    arn = ArnHelper(instance.arn)
    if instance.general_type != arn.general_type:
        instance.general_type = arn.general_type

    if instance.name != arn.name:
        instance.name = arn.name

    if instance.account_id != arn.account_id:
        instance.account_id = arn.account_id
