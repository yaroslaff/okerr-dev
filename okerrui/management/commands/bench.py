#!/usr/bin/env python
from django.core.management.base import BaseCommand, CommandError
from okerrui.models import Profile,Group,Indicator,Project
from optparse import make_option
from datetime import datetime,timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from myutils import *
#from dateutil.relativedelta import relativedelta
from django.db import connection
import time
import random

class Command(BaseCommand):
    help = 'Benchmark operations'

    def add_arguments(self,parser):
        ispec = parser.add_argument_group('Indicator specification')
        ispec.add_argument('--textid', default='bench', help='project TextID')
        ispec.add_argument('--inum', type=int, default=1, help='num of indicators 1..NUM')
        ispec.add_argument('--template', default='sslcert:{}', help='template for indicator')

        parser.add_argument('--iter', type=int, default=100, help='number of iterations')
        parser.add_argument('--geti', action='store_true', default=False, help='operation: get indicator')


    def geti_benchmark(self, options):
        random.seed()        
        p = Project.get_by_textid(options['textid'])
        print "Project:",p
        started = time.time()
        for i in xrange(1, options['iter']):
            # print "iteration",i
            name = options['template'].format(random.randint(1,options['inum']))
            indicator = p.get_indicator(name)
            # print indicator
        stopped = time.time()
        print "{} iterations in {:.2f} seconds ({:.2f} i/sec)".format(i, stopped - started, i / (stopped - started))
        

    def handle(self, *args, **options):
        if options['geti']:
            print "geti benchmark"
            self.geti_benchmark(options)
