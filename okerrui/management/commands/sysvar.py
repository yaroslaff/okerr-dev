#!/usr/bin/env python
from django.core.management.base import BaseCommand, CommandError
from okerrui.models import Profile,Group,Membership,SystemVariable
from optparse import make_option
from datetime import datetime,timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db import connection
from django.core.exceptions import ObjectDoesNotExist

from myutils import *
#from dateutil.relativedelta import relativedelta


class Command(BaseCommand):
    help = 'my okerr system variable administration'



    def add_arguments(self,parser):                
        parser.add_argument('--list', action='store_true', default=False, help='list all system variables')
        parser.add_argument('--reinit', action='store_true', default=False, help='reinit system variables')
        parser.add_argument('--var', dest='var', default=False, help='set new value for system variable')
        parser.add_argument('--delete', default=False, help='delete system variable')

    def handle(self, *args, **options):
        #print "options:",options
       

        if options['list']:
            for sv in SystemVariable.objects.all():
                print(sv)
        elif options['reinit']:
            SystemVariable.reinit()
        elif options['var']:
            try:
                (name,value) = options['var'].split('=',1)
                (sv,created) = SystemVariable.objects.get_or_create(name=name)
                sv.value=value
                sv.save()
            except ValueError:
                sv = SystemVariable.objects.get(name=options['var'])
                print(sv)
        elif options['delete']:
            name=options['delete']
            SystemVariable.objects.filter(name=name).delete()

