#!/usr/bin/env python
from django.core.management.base import BaseCommand, CommandError
from myauth.models import SignupRequest
from optparse import make_option
from datetime import datetime,timedelta
from django.utils import timezone
#from dateutil.relativedelta import relativedelta


class Command(BaseCommand):
    help = 'Manage signup requests'


    def add_arguments(self,parser):
        parser.add_argument('--list', action='store_true', help='list all profiles')
        parser.add_argument('--delete',action='store_true', default=False, help='delete selected ProfileArg')
        parser.add_argument('--user',default=False, help='user email')
        parser.add_argument('-b',dest='batch',default=False,action='store_true', help='brief output for batch mode')
        parser.add_argument('--really',default=False,action='store_true', help='really. (for dangerous operations)')


    def handle(self, *args, **options):
      
        if options['list']:
            for sr in SignupRequest.objects.all():
                print(sr)

        if options['user']:
            try:
                sr = SignupRequest.objects.get(email=options['user'])
            except SignupRequest.DoesNotExist:
                print("no such signup")
                return
            if options['delete']:
                if options['really']:
                    print(sr.delete())
                else:
                    print("really?")
