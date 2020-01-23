#!/usr/bin/env python
from django.core.management.base import BaseCommand, CommandError
from okerrui.models import Profile,Group,Membership,CheckArg,CheckMethod
from optparse import make_option
from datetime import datetime,timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db import connection

from myutils import *
#from dateutil.relativedelta import relativedelta


class Command(BaseCommand):
    help = 'okerr checkmethod management'


    def add_arguments(self,parser):
        parser.add_argument('--list', default=False, action='store_true', help='List all checkmethods')
        parser.add_argument('--show', default=False, action='store_true', help='Show one checkmethod')
        parser.add_argument('--reinit', default=False, action='store_true', help='Reinit cm configuration')
        parser.add_argument('--cm', default=False, help='Operate with this checkmethod')
        parser.add_argument('--addcm', default=False, action='store_true', help='add cm')
        parser.add_argument('--delcm', default=False, action='store_true', help='del cm')
        parser.add_argument('--carg', default=False, help='operate with this check arg')
        parser.add_argument('--addcarg', default=False, action='store_true', help='add check arg')
        parser.add_argument('--delcarg', default=False, action='store_true', help='del check arg')
        parser.add_argument('--cargdef', default=False, help='set default value for check arg')
        parser.add_argument('--really', default=False, action='store_true', help='required for dagerous ops like deleting')
        parser.add_argument('--enable', default=False, action='store_true', help='enable checkmethod')
        parser.add_argument('--disable', default=False, action='store_true', help='disable checkmethod')



    def showcm(self,cm):
        if cm.enabled:
            suffix=""
        else:
            suffix=" (disabled)"
        print("{}: {}{}".format(cm.codename, cm.name, suffix))
        for ca in cm.checkarg_set.all():
            print("  {} = {}".format(ca.argname, ca.default))
        print()
  
    def handle(self, *args, **options):
        
        
        User = get_user_model()


        if options['list']:
            for cm in CheckMethod.objects.all():
                self.showcm(cm)
        elif options['reinit']:
            CheckMethod.reinit_checkmethods(options['really'])
        elif options['addcm']:
            if options['cm']:
                cm = CheckMethod.objects.create(codename=options['cm'])
                cm.save()
            else:
                print("must have --cm codename")
        elif options['cm']:
            cm = CheckMethod.objects.filter(codename=options['cm']).first()
            if cm:
                if options['show']:
                    self.showcm(cm)
                elif options['delcm']:
                    if options['really']:
                        cm.delete()
                    else:
                        print("really?")
                elif options['addcarg']:
                    if options['carg']:
                        carg = CheckArg.objects.create(
                            cm=cm,argname=options['carg']) 
                elif options['carg']:
                    carg = CheckArg.objects.filter(
                        cm=cm,argname=options['carg']).first()
                    if carg:
                        if options['delcarg']:
                            carg.delete()
                        elif options['cargdef']:
                            carg.default=options['cargdef']
                            carg.save()
                    else:
                        print("no such check argument in cm {}".\
                            format(cm.codename))
                elif options['enable']:
                    if cm.enabled:
                        print("already enabled")
                    else:
                        print("enable")
                        cm.enabled = True
                        cm.save()
                elif options['disable']:
                    if cm.enabled:
                        print("disable")
                        cm.enabled = False
                        cm.save()
                    else:
                        print("already disabled")
            else:
                print("No such checkmethod")


            
