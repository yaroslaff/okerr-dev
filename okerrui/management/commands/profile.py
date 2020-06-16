#!/usr/bin/env python

from django.core import management
from django.core.management.base import BaseCommand, CommandError
from okerrui.models import Profile,Group,Membership, ProjectMember
from okerrui.training import tasks
from optparse import make_option
from datetime import datetime,timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db import connection

from myutils import *
#from dateutil.relativedelta import relativedelta

import random


class Command(BaseCommand):
    help = 'my okerr profile administration'

    def add_arguments(self, parser):
        parser.add_argument('--list', action='store_true', help='list all profiles')
        parser.add_argument('--pa', help='ProfileArg')
        parser.add_argument('--delete', action='store_true', default=False, help='delete selected profile (or profilearg)')
        parser.add_argument('--create', default=None, metavar='username', help='create user (with --pass)')
        parser.add_argument('--user', default=None, help='user email')
        parser.add_argument('--rename', default=None, metavar='NEW-EMAIL', help='New email')
        parser.add_argument('--patrol', action='store_true', default=False, help='patrol profiles')
        parser.add_argument('--tstage', default=None, help='set training stage (magic codes: prev, next, first)')
        parser.add_argument('-b', dest='batch', default=False,action='store_true', help='brief output for batch mode')
        parser.add_argument('--really', default=False,action='store_true', help='really. (for dangerous operations)')

        g = parser.add_argument_group('New profile options')
        g.add_argument('--pass', default=None, help='user pass')
        g.add_argument('--textid', default=None, help='first project textid')
        g.add_argument('--group', default=None, help='group name (to assign, list, view or alter)')
        g.add_argument('--days', type=int, default=0)
        g.add_argument('--infinite', action='store_true', default=False)

    def handle(self, *args, **options):
        #print "options:",options
        
        User = get_user_model()

        if options['create']:
            email = options['create']
            password = options['pass']
            
            if password is None:
                password = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(10))

            
            print("create user {}".format(email))
            
            try:
                User.objects.get(email = email)
            except User.DoesNotExist:
                print("No such user. good!")
            else:
                print("User {} already exists. sorry.".format(email))
                return
            
            print("create it.")

            user = User.objects.create_user(email, email, password)
            profile = Profile(user=user)
            profile.partner_name = ''
            profile.partner_id = ''
            profile.save()
            profile.inits(textid = options['textid'])

            print("created user {} pass {}".format(email, password))


            if options['group']:
                cmd = ['group', '--assign', options['group'], '--user', email]

                if options['days']:
                    cmd.extend(['--days', options['days']])
                elif options['infinite']:
                    cmd.append('--infinite')
                else:
                    raise CommandError('--group requires either --days NNN or --infinite')
                management.call_command(*cmd)
            else:
                print("do not forget to add to groups")

            return

        if options['rename']:
            u = User.objects.filter(username=options['user']).first()
            if u is None:
                print("no such user {}".format(options['user']))
            else:
                print("Rename {} to {}".format(u, options['rename']))
                u.username = options['rename']
                u.email = options['rename']
                u.save()

            for pm in ProjectMember.objects.filter(email=options['user']):
                print("Fix", pm)
                pm.email = options['rename']
                pm.save()

            return


        if options['patrol']:
            Profile.patrol(datetime.timedelta(seconds=0))
            return

        if options['tstage'] is not None:
            section='basic'
            stagelist = [t['code'] for t in tasks[section]]
            p = Profile.objects.filter(user__username=options['user']).first()

            if options['tstage'] == 'first':
                # tstage = tasks[section][0]['code']
                tstage = None
            elif options['tstage'] == 'next':
                if p.training_stage is not None:
                    section, curstage = p.training_stage.split(':', 1)
                    idx = stagelist.index(curstage)
                    tstage = stagelist[idx + 1]
                else:
                    tstage = stagelist[0]
            elif options['tstage'] == 'prev':
                section, curstage = p.training_stage.split(':', 1)
                idx = stagelist.index(curstage)
                if idx:
                    tstage = stagelist[idx - 1]
                else:
                    print("already first stage")
            elif options['tstage'] == 'list':
                print(stagelist)
                return
            elif options['tstage'] in stagelist:
                tstage = options['tstage']
            else:
                raise ValueError('Stage {} not found in {}'.format(options['tstage'], stagelist))

            if tstage is not None:
                # add section to stage if it's not None
                tstage = section+':'+tstage
            print("Set stage '{}' for user {}".format(tstage, options['user']))
            p.training_stage = tstage
            p.save()

        if options['list']:
            for p in Profile.objects.order_by('user__email'):
                if options['verbosity'] >= 2:
                    p.dump()
                else:
                    print(p.user.email)
                
        if options['user']:
            p = Profile.objects.filter(user__username=options['user']).first()
            if not p:
                # try, maybe parter:partner_id
                try:
                    partner, partner_id = options['user'].split(':') 
                except ValueError:
                    pass
                else:
                    p = Profile.objects.filter(partner_name = partner, partner_id = partner_id).first()
    
            if not p:                               
                print("no profile for", options['user'])
                sys.exit(1)
                return
        
            if options['pass']:
                print("set pass for", p)
                p.user.set_password(options['pass'])
                p.user.save()
            
            if options['pa']:
                pa = p.profilearg_set.filter(name=options['pa']).first()
                if pa:
                    if options['delete']:
                        print("deleted")
                        pa.delete()
                else:
                    print("no such ProfileArg '{}'".format(options['pa']))
            
            else:
                if options['delete']:
                    if not options['really']:
                        print("really?")
                        return
                    p.predelete()
                    p.delete()
                    return
                    
            p.dump()
            
