#!/usr/bin/env python
from django.core.management.base import BaseCommand, CommandError
from okerrui.models import Throttle
from optparse import make_option
from datetime import datetime,timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db import connection
from django.core.exceptions import ObjectDoesNotExist

from myutils import *
#from dateutil.relativedelta import relativedelta


class Command(BaseCommand):
    help = 'okerr throttle  administration'



    def add_arguments(self,parser):                
        parser.add_argument('--list', action='store_true', default=False, help='list all throttle keys')
        parser.add_argument('--flush', action='store_true', default=False, help='drop ALL throttle keys')
        parser.add_argument('--really', action='store_true', default=False, help='really')
        parser.add_argument('--delete', default=None, help='delete one throttle key')
        parser.add_argument('--cron', action='store_true', default=False, help='run cron task')

    def handle(self, *args, **options):
        #print "options:",options
       

        if options['list']:
            for th in Throttle.objects.all():
                print th
        elif options['flush']:
            if not options['really']:
                print "really?"
                return
            print Throttle.objects.all().delete()
        elif options['cron']:
            Throttle.cron()
        elif options['delete']:
            if not options['really']:
                print "really?"
                return
            name=options['delete']
            print Throttle.objects.filter(name=name).delete()

