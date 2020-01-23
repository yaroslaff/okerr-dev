#!/usr/bin/env python
from django.core.management.base import BaseCommand, CommandError
from okerrui.models import Project, Indicator, ProjectMember, Profile, Policy, SystemVariable
from optparse import make_option
from datetime import datetime,timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db import connection

from myutils import *
#from dateutil.relativedelta import relativedelta


class Command(BaseCommand):
    help = 'fix models and instances'

    models = [ Project, Policy, Indicator, Profile, ProjectMember, SystemVariable ]

    def add_arguments(self,parser):
        parser.add_argument('--save', default=False, action='store_true', help='save results')
        parser.add_argument('--model', default=None, help='for only this model (or ALL if not set)')
        parser.add_argument('--delete', default=False, action='store_true', help='delete all deleted_at records now')

        
    def handle(self, *args, **options):
        #print "options:",options
        
        User = get_user_model()

        if options['verbosity']>=2:
            print "set verbose"
            verbose=True
        else:
            verbose=False

        
        if options['delete']:
            for model in self.models:
                mname = model.__name__
                if options['model']:
                    # fix only one model
                    if mname != options['model']:
                        continue
                if not hasattr(model, 'deleted_at'):
                    continue
                
                
                for o in model.objects.filter(deleted_at__isnull=False):
                    if options['save']:
                        print "delete",o
                        if hasattr(o,'predelete'):
                            o.predelete()
                        o.delete()
            return
            


        for model in self.models:
            mname = model.__name__
            if options['model']:
                # fix only one model
                if mname != options['model']:
                    continue


            if getattr(model, 'fix_static', None):                
                model.fix_static(verbose=verbose, save=options['save'])

                
            print "fix model",mname
            if getattr(model, 'fix',None) is None:
                print "{} has no fix() method".format(mname)
                continue

            # fix each instance
            for i in model.objects.all():
                
                if options['verbosity'] >=2:
                    print "check {}: {}".format(mname, i)

                if i.fix(verbose=verbose):
                    if options['save']:
                        print "SAVE",i
                        i.save()
            


