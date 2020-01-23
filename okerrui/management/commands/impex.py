#!/usr/bin/env python
from django.core.management.base import BaseCommand, CommandError
from okerrui.models import Profile, ProjectTextID, ProfileArg, Group, Membership, Project, Policy, PolicySubnet, Indicator, ProjectMember, Membership, ProjectInvite, CheckMethod, CheckArg
from optparse import make_option
from datetime import datetime,timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db import connection, models, IntegrityError
import django.db.transaction
from django.conf import settings
from django.core.exceptions import ValidationError, ObjectDoesNotExist


import logging
import json
import time
import requests
import urllib.parse
from collections import OrderedDict

from okerrui.impex import Impex
from okerrui.cluster import RemoteServer, myci

import myutils
#from dateutil.relativedelta import relativedelta

#from transaction.models import myci, TransactionServer

#all_models = [Profile, Project, ProjectTextID, ProjectInvite, Policy, PolicySubnet, ProfileArg, Indicator, ProjectMember, Membership, CheckArg]

###            

User = get_user_model()


def get_content(filename=None, url=None, email=None):
    if filename:
        with open(filename, "r") as infile:
            return json.load(infile)
            
    if url and email:
        # combine url
        rurl = urllib.parse.urljoin(url,'/api/admin/export/{}'.format(email))
    
        r = requests.get(rurl)
        if r.status_code == 200:
            return json.loads(r.text)
        else:
            raise Exception('Error code: {} from url {}'.format(r.status_code, rurl))
            
    raise Exception('get_content: not enough data. filename: {} url: {} email: {}'.format(
        repr(filename),repr(url),repr(email)))


def setci_local(profile, ci):
    started = time.time()
    with django.db.transaction.atomic():
        profile.set_ci(ci, force=True)
        profile.tsave()
    print(("Done. Took {:.2f}s".format(time.time() - started)))

def setci_remote(email,ci):    
    
    me = RemoteServer.me()
    for rs in me.all_other():
        if rs.is_net():
            print(("update to rs {}: {}".format(rs.name, rs.url)))
            try:
                rs.set_ci(ci, email)
            except requests.exceptions.RequestException as e:
                print("FAILED: {}".format(str(e)))

def handle_sync(url, overwrite, verbosity):
    print("new sync", url)
    ie = Impex()
    ie.set_verbosity(verbosity)
    ie.sync(url, overwrite=overwrite)


def clone(data, email):
    oldemail = data['email']
    print("clone {} > {}".format(oldemail, email))
    data['email'] = email
    
    for p in data['Project']:
        newid = Project.gentextid()
        p['ProjectTextID'] = [ dict(textid = newid) ]  
    
    return data    
            
def UNUSED_handle_sync(url, overwrite, verbosity):
    ci = myci()
    
    rurl = urllib.parse.urljoin(url,'/api/admin/cilist')
    r = requests.get(rurl)
    if r.status_code == 200:
        userlist = r.text.split('\n')
    else:
        raise Exception('Error code: {} from url {}'.format(r.status_code, rurl))
        
    for email in userlist:
        if not email:
            continue
        try:
            luser = User.objects.get(email=email)
            profile = luser.profile
            if profile.ci == ci and not overwrite:
                raise Exception('user: {} ci: {} is mine and not overwrite!'.format(email, ci))
        except User.DoesNotExist:
            pass
        except Profile.DoesNotExist:
            # no profile. okay. we will re-create it. it's safe - we dont have profile anyway
            pass
    
        data = get_content(url = url, email = email)

        #overwrite always True here, because we always overwrite other-ci and check for local-ci above
        handle_import(data, True, verbosity) 

        

def handle_import(data, overwrite=False, verbosity=1):

    def user_exist(email):
        try:
            User.objects.get(email = email)
            return True
        except User.DoesNotExist:
            return False

    email = data['email']
    if verbosity >= 1:
        print("import",email)
    if user_exist(email):
        if overwrite:
            user = User.objects.get(email=email)
            user.profile.predelete()
            user.profile.delete()
            # user.delete() # no need to delete user, because profile.predelete deletes it
        else:
            print("sorry, already exist (no overwrite)")
            return
    
    ie = Impex()
    ie.set_verbosity(verbosity)
    ie.import_data(data)
    if verbosity >= 1:
        print(ie.get_stats())
    


def handle_export(profile, filename, verbosity):
    ie = Impex()
    ie.set_verbosity(verbosity)
    data = ie.export_data(profile)
    if filename:
        if verbosity >=1:
            print("write to",filename)
        with open(filename, "w") as outfile:
            json.dump(data, outfile, indent=4)     
    else:
        print(json.dumps(data, indent=4, sort_keys=True))

    if verbosity >= 1:
        print(ie.get_stats())

    
class Command(BaseCommand):
    help = 'okerr import/export'

    def add_arguments(self,parser):
        read_group = parser.add_argument_group('Read')
        read_group.add_argument('--list', action='store_true', help='list all profiles')
        read_group.add_argument('--info', action='store_true', help='brief summary info')
        read_group.add_argument('--cilist', metavar='ci', type=int, nargs='?', default=None, const=myci(), 
            help='list profiles for this ci (default, my: {})'.format(myci()))
        read_group.add_argument('--cluster', default=False, action='store_true', help='list cluster users')        
        read_group.add_argument('--hostinfo', metavar='host', nargs='?', const='*',default=None, help='hostinfo')        
        read_group.add_argument('--compare', default=False, action='store_true', help='compare users on all machines in cluster')        


        manage_group = parser.add_argument_group('Manage')
        manage_group.add_argument('--export', default=False, action='store_true', help='export profile for --user')
        manage_group.add_argument('--import', action='store_true', default=False, help='load one profile from (--file) OR (--url and --user)')
        manage_group.add_argument('--sync', metavar='MACHINE_URL', default=None, help='sync with remote url, e.g https://alpha.okerr.com/')
        manage_group.add_argument('--syncmap', action='store_true', default=False, help='sync according to map')
        manage_group.add_argument('--setci', type=int, metavar='CI', default=None, const=myci(), nargs='?', help='set ci for --user')
        manage_group.add_argument('--takeci', type=int, metavar='CI', default=None, help='set my ci for all users with this ci')
        manage_group.add_argument('--reanimate', default=False, action='store_true', help='reanimate everything for --user or all local')        

        wipe_group = parser.add_argument_group('Delete')
        wipe_group.add_argument('--ciwipe', metavar='ci', type=int, nargs='?', default = None, const=False, help='drop profiles for other ci')
        wipe_group.add_argument('--otherciwipe', default=False, action='store_true', help='drop profiles for all other ci')
        wipe_group.add_argument('--wipe', default = False, action='store_true', help='Wipe one user') 

        opts_group = parser.add_argument_group('Options')
#        opts_group.add_argument('--batch', '-b', action='store_true', help='batch mode (show briefly)')
        opts_group.add_argument('--user', default=None, help='user email')        
        opts_group.add_argument('-f','--file', metavar='FILENAME', default=None, help='work with this file')
        opts_group.add_argument('--url', metavar='URL', default=None, help='work with this URL. e.g. https://alpha.okerr.com/')
        opts_group.add_argument('--overwrite',action='store_true', default=False, help='delete old profile when importing')
        opts_group.add_argument('--dblog',action='store_true', default=False, help='log db queries')
        opts_group.add_argument('--remote', default=False, action='store_true', help='do remote operations if needed')
        opts_group.add_argument('--clone', default=False, action='store_true', help='modify imported data for cloning (e.g. set unused textids)')
        opts_group.add_argument('--skip', nargs='*', default=list(), help='modify imported data for cloning (e.g. set unused textids)')


    def handle(self, *args, **options):
        #print "options:",options
        
        user = None
        profile = None

        if options['verbosity'] >= 1:
            log = logging.getLogger('okerr')
            log.setLevel(logging.DEBUG)
            log.addHandler(logging.StreamHandler())

        # prepare data
        try:
            if options['user'] and not options['clone']:
                email = options['user']
                user = User.objects.get(email=options['user'])
                profile = user.profile
        except User.DoesNotExist:
            print("No such user")
        except Profile.DoesNotExist:
            print("No such profile")
    

        if options['dblog']:
            l = logging.getLogger('django.db.backends')
            l.setLevel(logging.DEBUG)
            l.addHandler(logging.StreamHandler())
                

        if options['skip']:
            for s in options['skip']:
                RemoteServer.skip(s)


        if options['hostinfo']:
            if options['hostinfo'] == 'all':
                rs = RemoteServer.me()
                for rrs in rs.all_rs():
                    print("== Hostinfo for %s" % rrs)
                    print(rrs.hostinfo())
                
            else:
                rs = RemoteServer(name = options['hostinfo'])
                print(rs.hostinfo())
            return

        if options['cluster']:
            print(json.dumps(settings.MACHINES, indent=4))                           
            return

        if options['compare']:
            ul = dict()
            users = list()
            badusers = list()
            me = RemoteServer.me()
            for rs in me.all_rs():
                ul[rs.name] = rs.list()
            
            for ulist in list(ul.values()):
                for u in ulist:
                    email = u['user']
                    if not email in users:
                        users.append(email)



            mnames = sorted(ul.keys())
            fmt = "{:<50}|{:1}| " + "{:<15}| " * (len(mnames))                        
            
            titles = list()
            for m in mnames:
                rs = RemoteServer(name = m)
                print(rs, rs.ci)
                titles.append("{} ({})".format(rs.name, rs.ci))
            print(fmt.format('EMAIL','X', *titles))
            print(fmt.format('-'*50,'-',*["-"*15 for x in range(len(mnames))]))
            
            
            for username in users:
                cil = list()
                for m in mnames:                    
                    urec = [urec for urec in ul[m] if urec['user'] == username]
                    if urec:
                        cil.append(urec[0]['ci'])
                    else:
                        cil.append('-')
            
                if cil[1:] == cil[:-1]:
                    cil.insert(0,'')
                    if options['verbosity']>=1:
                        print(fmt.format(username, *cil))
                else:
                    cil.insert(0,'X')
                    print(fmt.format(username, *cil))
                    
            

            return


        if options['reanimate']:
            if profile:
                print("single reanimate", profile)
                profile.reanimate()
            else:
                for p in Profile.objects.filter(ci = myci()):
                    print("reanimate",p)
                    p.reanimate()
            return

        if options['info']:
            print("Host: {} Cluster: {} ci: {}".format(repr(settings.HOSTNAME), repr(settings.CLUSTER_NAME), myci()))
            print("Profiles: {} / {}".format(Profile.objects.filter(ci=myci()).count(), Profile.objects.count()))
            return

        if options['list']:
            for p in Profile.objects.all():
                    print(p.ci, p.user.username)
        elif options['cilist'] is not None:
            for p in Profile.objects.filter(ci=options['cilist']).all():
                print(p.user.username)
        elif options['wipe']:
            if not (user or profile):
                print("need either user ({}) or profile ({})".format(user, profile))
            if user:
                user.delete()
            if profile:
                profile.delete()
            print("deleted")
        elif options['ciwipe'] is not None:
            if options['ciwipe'] == myci():
                print("cannot ciwipe for my own ci {}".format(myci()))
                return
            for p in Profile.objects.filter(ci=options['ciwipe']).all():
                if options['verbosity']>=1:
                    print("delete {} ci: {}".format(p, p.ci))
                p.user.delete()
                p.delete()
        elif options['otherciwipe']:
            ci = myci()
            for p in Profile.objects.all():
                if p.ci == ci:
                    if options['verbosity']>=1:
                        print("skip profile {} ci: {}".format(p, p.ci))
                else:
                    if options['verbosity']>=1:
                        print("delete {} ci: {}".format(p, p.ci))
                    p.user.delete()
                    p.delete()
        
        elif options['export']:
            if profile:
                handle_export(profile, options['file'], options['verbosity'])       
            else:
                print("Need --user")
 
        elif options['import']:
            data = get_content(filename = options['file'], url = options['url'], email = options['user'])
            if options['clone']:
                data = clone(data, options['user'])                        
            handle_import(data, options['overwrite'], options['verbosity'])
 
        elif options['sync']:
            handle_sync(options['sync'], options['overwrite'], options['verbosity'])
 
        elif options['syncmap']:            
                ie = Impex()
                ie.set_verbosity(options['verbosity'])
                ie.syncmap()
                return

        elif options['takeci'] is not None:            
            for profile in Profile.objects.filter(ci=options['takeci']):
                print("process profile", profile)
                ## profile = Profile.objects.get(user__email = options['user'])
                setci_local(profile, myci())
                if options['remote']:
                    setci_remote(profile.user.username, myci())
                else:
                    print("skip remote, because no --remote")
            return
            
        elif options['setci'] is not None:            
            if options['user']:
                profile = Profile.objects.get(user__email = options['user'])
                setci_local(profile, options['setci'])
                if options['remote']:
                    setci_remote(options['user'], options['setci'])
                else:
                    print("skip remote, because no --remote")
            else:
                print("need --user")
            return

        
        
            print("setci {} for user {}".format(options['setci'], email))
            # change for profile and projects
            ci = options['setci']
            
            profile.set_ci(options['setci'])
            profile.save()
        else:
            print("Whaat?")    
            
            
