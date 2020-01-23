#!/usr/bin/env python
from django.core.management.base import BaseCommand, CommandError
from okerrui.models import Project, ProjectTextID, Profile,Group,Membership
from optparse import make_option
from datetime import datetime,timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db import connection

import json

from myutils import *
#from dateutil.relativedelta import relativedelta


class Command(BaseCommand):
    help = 'my okerr keys administration'
    """
    option_list = BaseCommand.option_list + (

        make_option('--dump',
            dest='dump',
            action='store_true',
            help='dump all keys in nice JSON format',
            default=False),

        make_option('--export',
            dest='export',
            action='store_true',
            help='dump all keys in nice JSON format, but cut away some data (for keys-template.json)',
            default=False),


        make_option('--raw',
            dest='raw',
            action='store_true',
            help='print jkeys in raw (string) format',
            default=False),


        make_option('--textid',
            dest='textid',
            # action='store_true',
            help='filter by TextID',
            default=False),

        make_option('--id',
            dest='id',
            # action='store_true',
            help='filter by id',
            default=False),


        )
    """
    
    def add_arguments(self,parser):
        parser.add_argument('--dump', action='store_true',help='Dump all keys in nice JSON format', default=False)
        parser.add_argument('--export', action='store_true',help='Same as dump, but cut away some data (for keys-template.json)', default=False)
        parser.add_argument('--raw', action='store_true',help='Print in raw JSON format (not pretty)', default=False)
        parser.add_argument('--textid', help='Filter by project textid', default=False)
        parser.add_argument('--id', help='Filter by project id (number)', default=False)
        

    def handle(self, *args, **options):
        #print "options:",options
        
        User = get_user_model()

        if options['textid']:
            tid = ProjectTextID.objects.get(textid = options['textid'])
            p = tid.project
        elif options['id']:
            p = Project.objects.get(pk = int(options['id']))
            
        else:
            print "require textid to find project"    
            return
            
        if options['raw']:            
            print p.jkeys
                    
        if options['dump']:            
            d = json.loads(p.jkeys)
            print json.dumps(d, sort_keys=True, indent=4, separators=(',', ': '))

        if options['export']:            
            d = json.loads(p.jkeys)
            if '@access' in d:
                del d['@access']
            d['mylib']={}
            d['servers']={'server1': {'@include conf:anyserver':''}}
            print json.dumps(d, sort_keys=True, indent=4, separators=(',', ': '))


            
