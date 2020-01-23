from django.db import models
from django.utils import timezone
import datetime
import string
import random

# Create your models here.
class SignupRequest(models.Model):
    email = models.CharField(max_length=200) 
    created = models.DateTimeField(default=timezone.now, blank=True)
    code = models.CharField(max_length=200)

    def gencode(self):
        self.code = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))

    def __str__(self):
        return self.email

    @staticmethod
    def cron():
        # delete old signup requests
        time = timezone.now() - datetime.timedelta(days=1)
        SignupRequest.objects.filter(created__lt=time).delete()
        
