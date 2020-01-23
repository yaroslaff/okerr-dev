#!/usr/bin/env python
from django.core.management.base import BaseCommand, CommandError
from okerrui.models import Profile,Group,GroupArg,Membership,ProfileArg
from optparse import make_option
from datetime import datetime,timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from myutils import *
import json

from django.core.exceptions import ObjectDoesNotExist
#from dateutil.relativedelta import relativedelta

def table():
    g = Group.get_calculated()
    keys = sorted(
        Group.group_names(),
        key = lambda name: g[name]['_price'] if '_price' in g[name] else 0)
    keys.remove('Admin')
    
    titlekeys = list(keys)
    titlekeys.insert(0,'')
    tpl = "{0:20}|"
    for i in range(1,len(titlekeys)):
        tpl += "{"+str(i)+":>13}|"


    l = ['--' for x in range(0,len(titlekeys))]

    print(tpl.format(*titlekeys))    
    print(tpl.format(*l))
    
    for attr in ['maxindicators','minperiod','teamsize','maxprojects','maxstatus','settextname',
            '_price','_base_checks','_quick_checks','_price_1indicator','_price_1check']:
        v = list()
        v.append(attr)

        for gname in keys:
            v.append(g[gname].get(attr,''))
        print(tpl.format(*v))

    # perks
    print()
    
    perkfirst=['_price', '_price_1check']
    perkskip=['_base_maxindicators','_base_checks','_price_1indicator','_quick_checks']
    
        
    perknames = sorted(
        Group.perk_names(),
        key = lambda name: g[name]['_price'] if '_price' in g[name] else 0)
    
        
    for perkname in perknames:
        #print perkname
        #print json.dumps(g[perkname], indent=4)
        outline=""
        
        # first keys
        for k in perkfirst:
            if k in g[perkname]:
                outline+="{}={} ".format(k, g[perkname][k])
        # other keys        
        for k in list(g[perkname].keys()):
            if not (k in perkfirst or k in perkskip):
                outline+="{}={} ".format(k, g[perkname][k])

        print("{0:25}: {1}".format(perkname, outline))


class Command(BaseCommand):
    help = 'Manage group membership'

    def add_arguments(self,parser):
        parser.add_argument('--list', nargs='?', default=None, const='all',help='list all groups or one --group')
        parser.add_argument('--days', type=int, default=0)
        parser.add_argument('--infinite', action='store_true', default=False)
        parser.add_argument('--assign', default=None, metavar='GROUP', help='assign --user to this group [for --days]')
        parser.add_argument('--force', default=False, action='store_true', help='force (e.g. to add to 2nd group)')
        parser.add_argument('--revoke', default=None, metavar='GROUP', help='revoke --user from this GROUP')        
        parser.add_argument('--refill', default=False, action='store_true', help='refill --user')        
        parser.add_argument('--user', default=None, help='only this email')
        parser.add_argument('--wipe', default=None, action='store_true')
        parser.add_argument('--group', default=None, help='group name (to assign, list, view or alter)')
        parser.add_argument('--all', default=False, action='store_true', help='all users (for refill)')
        parser.add_argument('--setvar', default=False, nargs=2, metavar=('VarName','Value'), help='')
        parser.add_argument('--delvar', metavar='VarName',default=False, help='')
        parser.add_argument('--reinit', action='store_true', default=False, help='reinit all groups')
        parser.add_argument('--delete', action='store_true', default=False, help='reinit can delete groups and group args')
        parser.add_argument('--ro', action='store_true', default=False, help='reinit read only')
        parser.add_argument('-b', dest='batch',action='store_true',default=False, help='brief output for batch mode')
        parser.add_argument('--table', dest='table',action='store_true',default=False, help='output as table')


    
    

    def handle(self, *args, **options):
        #print "options:",options
        
        def dump_group(name, data):
            group = Group.objects.get(name=name)
            nm = group.membership_set.count()
            print("Group {} ({} membership)".format(name, nm))
            print(json.dumps(data, indent=4))
            print()

        
        User = get_user_model()
        
        if options['reinit']:
            Group.reinit_groups(delete=options['delete'], readonly=options['ro'])
            return
    
        if options['refill']:            
            # prepare user QuerySet        
            if options['all']:
                qs = User.objects.all()
            elif options['user']:
                qs = User.objects.filter(username=options['user'])
            else:
                print("need --user or --all")

            for user in qs:                     
                print("refill user", user)
                profile = user.profile
                profile.profilearg_set.all().delete()
                for m in Membership.objects.filter(profile=profile):
                    print(".. refill user {} membership {}".format(user,m))
                    m.group.refill(m.profile,m.expires) 
            return


        if options['table']:
            table()
            return

        if options['list']:

            gconf = Group.get_gconf()

            if options['group']:
                print(json.dumps(gconf[options['group']], indent=4))
            else:            
                for gname in sorted(gconf.keys()):
                    gdata = gconf[gname]
                    if options['list'] == 'all':
                        dump_group(gname, gdata) 
                    elif options['list'].startswith('group') and not gname.startswith('perk:'):
                        dump_group(gname, gdata) 
                    elif options['list'].startswith('perk') and gname.startswith('perk:'):
                        dump_group(gname, gdata) 
            return

        if options['setvar']:
            g = Group.objects.get(name=options['group'])
            varname = options['setvar'][0]
            varval = int(options['setvar'][1])
            print("set {} = {} in {}".format(varname,varval,g))
            
            try:
                ga = g.grouparg_set.get(name=varname)
                ga.value=varval
            except ObjectDoesNotExist:
                print("No such group argument {} in group {}, create".format(varname,options['group']))
                ga = GroupArg(group=g, name=varname, value=varval)
            ga.save()
                
            return
        
        if options['delvar']:
            g = Group.objects.get(name=options['group'])

            x = GroupArg.objects.filter(group=g, name=options['delvar']).delete()        
            if x[0]:
                print("deleted {} grouparg '{}' in group '{}'".format(x[0],options['delvar'],options['group']))
            else:
                print("nothing deleted")
                
            return


        if options['user']:                                               
            user = User.objects.filter(username=options['user']).first()
            if user:
                print(user)
            else:
                print("no such user!")
            p = Profile.objects.filter(user=user).first()
            
            if p: 
                if options['wipe']:
                    print("delete {} from all groups".format(p.user.username))
                    p.wipe()           
                elif options['assign']:
                    print("assign to group {}".format(options['assign']))
                    g = Group.objects.filter(name=options['assign']).first()
                    if not g:
                        print("No such group",options['assign'])
                        return
                    kwa={}


                    if options['infinite']:
                        days=0
                    elif options['days']:
                        days=options['days']
                    else:
                        print("need --days NNN or --infinite")
                        return

                        
                    kwa['days']=days
                    if days:
                        exp = timedelta(**kwa)
                    else:
                        exp=None

                    p.assign(group=g,time=exp, force_assign = options['force'])
                elif options['revoke']:
                    g = Group.objects.filter(name=options['revoke']).first()
                    if not g:
                        print("No such group",options['revoke'])
                        return
                    print("revoke user {} from group {}".format(user.username, g.name))
                    rc = Membership.objects.filter(profile=p,group=g)[0].delete()
                    print(rc)
                    # rc = ProfileArg.objects.filter(profile=p,group=g).delete()
                    # print rc
                    
                                         
                else:              
                    # if no command for user, then just dump
                    p.dumpgroupinfo()
            else:
                print("no profile for {}".format(options['user']))
        else:
            for p in Profile.objects.all():
                groupstr=""
                gn=0
                for name,exp in p.groups().items():
                    if gn>0:
                        groupstr+=", "
                    groupstr+=name
                    gn+=1
                print("{}: {}".format(p.user.username,groupstr))


