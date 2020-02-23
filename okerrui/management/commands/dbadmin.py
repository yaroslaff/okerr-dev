#!/usr/bin/env python
from django.core.management.base import BaseCommand, CommandError
from django.core import management
from django.core.management.commands import loaddata
from okerrui.models import Profile,Group,Membership
from optparse import make_option
from datetime import datetime,timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db import connection
from django.apps import apps

from myutils import *
#from dateutil.relativedelta import relativedelta


class Command(BaseCommand):
    help = 'my okerr database administration'


    def add_arguments(self,parser):                
        parser.add_argument('--list', action='store_true', default=False, help='List all tables')
        parser.add_argument('--drop', action='store_true', default=False, help='print DROP sql statement instead of table name, for use with ./manage.py dbshell')
        parser.add_argument('--all', action='store_true', default=False, help='list ALL tables (not only okerrui_*)')
        parser.add_argument('--stat', action='store_true', default=False, help='stat for all application models')
        parser.add_argument('--reinit', action='store_true', default=False, help='flush and reinit database')
        parser.add_argument('--really', action='store_true', default=False, help='really for reinit')




    def handle(self, *args, **options):
        #print "options:",options
        
        User = get_user_model()


        if options['reinit']:
            if options['really']:
                print("Reset database")
                management.call_command('flush', '--noinput')
                # management.call_command('group', '--reinit')
                management.call_command('sysvar', '--reinit')
                management.call_command('checkmethod', '--reinit', '--really')
                management.call_command('oauth', '--reinit')
                # management.call_command('impex','--reinit')
            else:
                print("You are not --really")

            return

        if options['list']:
            
            tables = connection.introspection.table_names()
            seen_models = connection.introspection.installed_models(tables)
            
            print("SET foreign_key_checks = 0;")
            for table in tables:
                if table.startswith("okerrui_") or options['all']:
                    if options['drop']:
                        print("DROP TABLE {};".format(table))
                    else:
                        print(table)
            print("SET foreign_key_checks = 1;")
        elif options['stat']:
            print("stat")
            for appname in sorted(['okerrui','myauth']):
                app_models = apps.get_app_config(appname).get_models()
                for model in sorted(app_models,key=lambda x: x.__name__):
                    fullname=appname+':'+model.__name__
                    print("{} {}".format(fullname.ljust(25,' '), model.objects.count()))
            
            
