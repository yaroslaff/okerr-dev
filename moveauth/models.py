# transaction models
from django.db import models, IntegrityError
from django.conf import settings
from django.utils import timezone
from django.core.exceptions import FieldDoesNotExist, ObjectDoesNotExist
from django.forms.models import model_to_dict
from django.db.models import Q


#import okerrui.models
import json
import time
import requests
import hashlib
import random
import string
import datetime

#from operator import itemgetter

import myutils

SECRET = 'sk824jdshvSOckzjxhkjl23sdcvzhjzxvzmnqw3r2asdsd0s01232sdfklSD'

class MoveAuthTicket(models.Model):
    created = models.DateTimeField(auto_now=True, null=True, db_index=True)
    ticket = models.CharField(max_length=100, default='')
    email = models.CharField(max_length=100, default='')    

    lastcron = None

    def __unicode__(self):
        return "{}: {}".format(self.email, self.ticket)    
        
    @staticmethod
    def generate(email):
        l = 50
        ticket = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(l))

        mat = MoveAuthTicket(email=email, ticket = ticket)
        mat.save()
        return ticket 
    
    @staticmethod
    def get_ticket(url, email):
        # url is url of remote mkticket page
        rd = dict()
        rd['email'] = email
        rd['time'] = int(time.time())
        rd['signature'] = MoveAuthTicket.request_signature(rd)
        
        # print "post to",url
        r = requests.post(url, data = rd)
        
        if r.status_code != 200:
            return None
        return r.text
        
    @staticmethod
    def request_signature(r):
        rstr='{}:{}:{}'.format(r['email'], r['time'], SECRET)
        signature = hashlib.sha256(rstr).hexdigest()
        return signature

    @classmethod
    def cron(cls):
        modelcrontime = 30
        if cls.lastcron and int(time.time()) < cls.lastcron+modelcrontime:
            return            
        cls.lastcron=int(time.time())        

        now = timezone.now()
        old = now - datetime.timedelta(0,120)
    
        cls.objects.filter(created__lt=old).delete()

