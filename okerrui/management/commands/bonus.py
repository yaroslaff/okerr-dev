#!/usr/bin/env python
from django.core.management.base import BaseCommand, CommandError
from okerrui.models import Profile,Group,Membership
from okerrui.bonuscode import BonusCode, BonusActivation
from optparse import make_option
from datetime import datetime,timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from myutils import *
from oman import OMan, ArgError
#from dateutil.relativedelta import relativedelta


class Command(BaseCommand):
    help = 'Manage bonus codes'
    
    def __init__(self):
        super(Command,self).__init__()

        self.oman = OMan(BonusCode,'name')
        self.oman.reqarg('create','group')
        
        # Not needed, because this implemented not in OMan
        #self.oman.reqarg('use','email')
        #self.oman.reqarg('check','email')

        
        self.oman.table_key_field(Group, 'name')
        self.oman.seconds_column('reactivation')
        self.oman.seconds_column('expiration')
        self.oman.seconds_column('time')

    
    def add_arguments(self,parser):                

        parser.add_argument('--user', metavar='EMAIL', default=None, help='User by email')
        parser.add_argument('--act', action='store_true', default=False, help='Show activations for --user')
        parser.add_argument('--delact', action='store_true', default=False, help='Delete activations for --user')
        parser.add_argument('--use', metavar='BONUSCODE', default=None, help='Use bonus code')
        parser.add_argument('--check', metavar='BONUSCODE', default=None, help='Just check bonus code')
        parser.add_argument('--cron', action='store_true', default=False, help='Run cron tasks once')
        parser.add_argument('--wipe', metavar='CODE', default=None, help='Wipe activations for this code')
        parser.add_argument('--generate', metavar='CodenameOrID', nargs='+', default=False, help='Generate code')


        self.oman.args(parser)
            


    def wipe(self,codename):
        bc = BonusCode.objects.get(name=codename)
        print "bonus code: {}".format(bc)
        for ba in BonusActivation.objects.filter(BonusCode=bc):
            ba.delete()
        print "deleted"

    def handle(self, *args, **options):
        #print "options:",options
                                
        User = get_user_model()                
        
        if options['act']:
            try:
                if options['user']:
                    u = User.objects.get(email=options['user'])
                    profile = Profile.objects.get(user=u)
                    qs = BonusActivation.objects.filter(user=u)
                else:
                    qs = BonusActivation.objects.all()
            
                for bact in qs:
                    print bact
                    
            except ObjectDoesNotExist:
                print "No such user with email '{}'. Sorry.".format(options['user'])
                return

        elif options['delact']:
            try:
                u = User.objects.get(email=options['user'])
                profile = Profile.objects.get(user=u)
            
                for bact in BonusActivation.objects.filter(user=u):
                    print "DELETE",bact
                    bact.delete()      
                          
            except ObjectDoesNotExist:
                print "No such user with email '{}'. Sorry.".format(email)
                return

        
        elif options['generate']:
            bc = self.oman.get(options['generate'][0])
            if len(options['generate'])==2:
                num = int(options['generate'][1])
            else:
                num = 1                                      
            if bc:
                for n in xrange(num):
                    print bc.generate()
                    
                    
        elif options['use'] or options['check']:
            if not options['user']:
                print "require --user for --use or --check"
                return
            bonuscode = options['use'] or options['check']
            print "bonuscode:",bonuscode
            email = options['user']
            try:
                u = User.objects.get(email=email)
                profile = Profile.objects.get(user=u)
            except ObjectDoesNotExist:
                print "No such user with email '{}'. Sorry.".format(email)
                return
            if options['use']:
                apply=True
            else:
                apply=False
                
            out = BonusCode.use(bonuscode,profile,apply)
            print out
        elif options['wipe']:
            self.wipe(options['wipe'])        
        elif options['cron']:
            BonusActivation.cron()
        else:
            try:
                self.oman.handle(options)
            except ArgError as e:
                print e
        
