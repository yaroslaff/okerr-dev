#!/usr/bin/env python
from django.core.management.base import BaseCommand, CommandError
from okerrui.models import Project, ProjectTextID, Profile,Group,Membership,ProjectMember
from optparse import make_option
from datetime import datetime,timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db import connection

import json

from myutils import *
#from dateutil.relativedelta import relativedelta


class Command(BaseCommand):
    help = 'okerr project management'


    def add_arguments(self,parser):
        parser.add_argument('--all', default=False, action='store_true', help='list all projects')
        parser.add_argument('--textid', default=None, help='project TextID')
        parser.add_argument('--id', default=None, help='project by guessable ID (db id, textid, rid, srid or name)')
        parser.add_argument('--owner', default=None, help='owned by user email')
        parser.add_argument('--user', default=None, help='project where user is member')
        parser.add_argument('--name', default=None, help='projects with this name')
        parser.add_argument('--resetjkeys', default=False, action='store_true', help='reset project keys')
        parser.add_argument('--jkeys', default=False, action='store_true', help='display project keys')
        parser.add_argument('--exportjkeys', default=False, action='store_true', help='export project keys (to use as template)')
        parser.add_argument('--addtextid', default=None, help='add text id')
        parser.add_argument('--adduser', default=None, help='add --user to project')
        parser.add_argument('--rmuser', default=None, help='remove --user from project')
        parser.add_argument('--summary', default=None, action='store_true', help='send summary')
        parser.add_argument('--limit', default=None, type=int, help='limit (0 - disable, 1 - enable)')
        parser.add_argument('--dellog', default=False, action='store_true', help='delete logs')


    def id2project(self, pid):
        # id
        try:
            p = Project.objects.get(pk=int(pid))
        except (Project.DoesNotExist, ValueError):
            pass
        else:        
            return [p]
       
        # textid
        p = Project.get_by_textid(pid)
        if p is not None:
            return [p]
        
        # rid
        try:
            p = Project.objects.get(rid=pid)
        except Project.DoesNotExist:
            pass
        else:        
            return [p]

        
        # srid
        pqs = Project.objects.filter(owner__profile__rid=pid)
        if pqs.count() > 0:
            return pqs

        
        # name        
        p = Project.objects.filter(name=pid).first()
        if p is not None:
            return [p]

        return None

    def handle(self, *args, **options):
        #print "options:",options
        
        User = get_user_model()


        if options['all']:
            for p in Project.objects.all():                
                p.dump()
            
        elif options['id']:
            p = self.id2project(options['id'])
            worked = False
            if p is None:
                print("No such project!")
                return
            
            if len(p) == 1:
            
                pp = p[0]
                    
                if options['resetjkeys']:
                    print("Reset JKEYS for project {}".format(p))
                    pp.jkeys = settings.JKEYS_TPL
                    pp.addkey('@access')
                    pp.addkey('client','','@access')
                    pp.save()
                    worked = True

                if options['dellog']:
                    print(pp.logrecord_set.all().delete())
                    worked = True

                if options['exportjkeys']:
                    k = json.loads(pp.jkeys)
                    # reset something
                    k['@access'] = dict()
                    k['servers'] = dict()
                    k['mylib'] = dict()

                    print(json.dumps(k, indent=4, separators=(',',': '), sort_keys=True))
                    worked = True


                if options['addtextid']:
                    k = json.loads(pp.jkeys)
                    if pp.addtextid(options['addtextid']):
                        pp.tsave()
                        print("done")
                    else:
                        print("sorry, failed")
                    worked = True


                if options['jkeys']:
                    k = json.loads(pp.jkeys)
                    print(json.dumps(k, indent=4, separators=(',',': '), sort_keys=True))
                    worked = True

                if options['adduser']:
                    user = User.objects.get(email=options['adduser'])
                    pp.add_member(user)
                    worked = True

                if options['rmuser']:
                    user = User.objects.get(email=options['rmuser'])
                    pp.remove_member(user)
                    worked = True
                        
                if options['summary']:
                    pp.sendsummary('requested from CLI')
                    worked = True
                
                if options['limit'] is not None:
                    if options['limit'] == 0:
                        pp.limited = False
                    else:
                        pp.limited = True
                    pp.save()
                        
            if not worked:
                for pp in p:
                    pp.dump()
            
                
        elif options['owner']:
            user = User.objects.get(email=options['owner'])
            print("projects owned by user",user)
            for p in user.project_set.all():
                p.dump()
        elif options['user']:
            user = User.objects.get(email=options['user'])
            print("projects with user",user)
            for pm in ProjectMember.objects.filter(email=user):
                pm.project.dump()
        elif options['name']:
            p = Project.objects.get(name=options['name'])
            p.dump()
        
            
