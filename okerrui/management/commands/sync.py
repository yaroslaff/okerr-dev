#!/usr/bin/env python
from optparse import make_option
import datetime 
import time
import pytz
import json
import requests
import urlparse

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.db.models import Q, Count
import django.db.transaction
import resource


from okerrui.models import Profile, Group, Membership, Project, Indicator, Policy, ProjectMember
from okerrui.bonuscode import BonusCode, BonusActivation
from okerrui.datasync import Sync
from transaction.models import Transaction, TransactionEngine, TransactionError, TransactionServer, myci

from myutils import *


# from oman import OMan, ArgError
#from dateutil.relativedelta import relativedelta

def make_srid(srid):
    """ return srid from srid or email """
    # check if this is srid
    try:
        p = Profile.objects.get(rid = srid)
    except ObjectDoesNotExist:
        pass
    else:
        return p.rid
        
    try:
        p = Profile.objects.get(user__email = srid)
    except ObjectDoesNotExist:
        pass
    else:
        return p.rid
    
    # if not resolved, return as-is, maybe we dont know this srid here yet
    return srid
        
    

def counts(te):
    
    models = list(te.model_order)
    models.append(get_user_model())
    c = dict()

    for m in models:
        mname = m.__name__                    
        c[mname] = m.objects.count()
    return c


def get_profile(key):
    """
        return profile by RID or email
    """
    try:
        p = Profile.objects.get(rid=key)
        return p
    except ObjectDoesNotExist as e:
        try:
            p = Profile.objects.get(user__email=key)
            return p
        except ObjectDoesNotExist as e:
            return None


def dhms(sec, sep=" ", num=2):
    out=""
    nn=0
    t={'d': 86400,'h': 3600,'m': 60,'s': 1}
    for k in sorted(t,key=t.__getitem__,reverse=True):
        if sec>t[k]:
            if nn == num:
                break
            nn+=1
            n = int(sec/t[k])
            sec-=n*t[k]
            out+="%d%s%s" % (n,k,sep)
    return out.strip()
    


# methods

def setci_local(profile, ci):
    started = time.time()
    with django.db.transaction.atomic():
        profile.set_ci(ci, force=True)
        profile.tsave()
    print "Done. Took {:.2f}s".format(time.time() - started)

def setci_remote(srid,ci,force=False):    
    for ts in TransactionServer.objects.all():
        print "update to ts {}: {}".format(ts.machine, ts.url)
        ts.setci(ci, srid)
    
def ssync(srid, machine):
    print "ssync srid: {} from machine: {}".format(srid, machine)
    p = get_profile(srid)              
               
    if machine is None:
        if p is None:
            print "ERR. Unknown SRID, email and no machine"
            return
        tsrv = TransactionServer.ciserver(p.ci)
    else:
        tsrv = TransactionServer.objects.get(machine=machine)
        
    tsrv.ssync(srid)

def reanimate(profile):
    print "reanimate for", profile
    for o in godeep(profile):
        if getattr(o,'transaction_reanimate',None):
            print "reanimate",o
            o.transaction_reanimate()
            o.save()
        

def takeall(machine, hostname=None):
    """ take all known projects from remote machine """
    my_ci = myci(hostname)
    machine_ci = myci(machine)
    print "take from from {}:{} to me {}:{}".format(machine, machine_ci, hostname, my_ci)

    for p in Profile.objects.filter(ci=machine_ci):
        print "take project",p.rid,p
        take(p.rid)

def take(srid, machine=None):
    p = get_profile(srid)
    
    if machine is None:
        if p is None:
            print "ERR. Unknown SRID, email and no machine"
            return
        tsrv = TransactionServer.ciserver(p.ci)
    else:
        tsrv = TransactionServer.objects.get(machine=machine)
    
    if p is None:
        rid = srid
    else:
        rid = p.rid
    tsrv.take(rid)
    

def godeep(profile=None, ci=None):
    if profile is None:
        if ci is None:
            pqs = Profile.objects.all()
        else:
            pqs = Profile.objects.filter(ci=ci)
        for p in pqs:
            godeep(p)
        
    else:
        yield profile    
        for project in profile.user.project_set.all():
            yield project            
            for indicator in project.indicator_set.all():
                yield indicator
            

def cicheck():
    for profile in Profile.objects.all():
        ci = profile.ci
        print profile,"ci:",ci
        
        for project in profile.user.project_set.all():
            if project.ci != ci:
                print "ERR:",project, project.ci
            
            for indicator in project.indicator_set.all():
                if indicator.ci != ci:
                    print "ERR:",indicator, indicator.ci
            

def compare(url):

    def cmpi(i1,i2):
        #print "cmpi i1:",i1
        #print "cmpi i2:",i2
        
        if i1['status'] == i2['status']:
            return False # no difference
        else:
            print "{} ({}) != {} ({})".format(i1['name'],i1['status'],i2['name'],i2['status'])
            return True

    def cmpproject(s1, s2, textid):       
    
        def get_indicators(srv, textid):
            rurl = urlparse.urljoin(srv['url'],'/rawpjson/{}'.format(textid))
            r  = requests.get( rurl )

            if r.status_code != 200:
                print "ERROR", rurl, r.status_code, r.text
                return

            pdata = json.loads(r.text)
            return pdata['indicators']
        
        i1 = get_indicators(s1,textid)
        i2 = get_indicators(s2,textid)
        
        print "{}@{}: {} indicators, {}@{}: {} indicators".format(
            textid, s1['machine'], len(i1),
            textid, s2['machine'], len(i2))
    
        for iname in i1:
            if not iname in i2:
                print "! {} indicator {} only on {} (not on {})".format(textid, iname, s1['machine'], s2['machine'])
    
        for iname in i2:
            if not iname in i1:
                print "! {} indicator {} only on {} (not on {})".format(textid, iname, s2['machine'], s1['machine'])

        di = 0     
        for iname in i1.keys():
            if iname in i2:
                if cmpi(i1[iname], i2[iname]):
                    di+=1
        if di>0:
            print "{} indicators different".format(di)

    def dinlist(d, l):
        for li in l:
            if d == li:
                return True
        return False    
    
    def compare_listdict(orig, l, name):
        for oi in orig:
            if not dinlist(oi, l):
                print "original:"
                print oi
                
        for oi in l:
            if not dinlist(oi, orig):
                print name,":"
                print oi
                


    srv=dict()

    try:
        r = requests.get( urlparse.urljoin(url, '/api/listcluster') )
    except requests.exceptions.ConnectionError:
        print "cannot list cluster from URL",urlparse.urljoin(url, '/api/listcluster')
        return

    cluster = json.loads(r.text) # data in origin server

    for suffix in ['/api/listcluster', '/api/plist']:

        scode = suffix.split('/')[-1]

        cd = dict() # cluster data 

        ourl = urlparse.urljoin(url, suffix)
        r = requests.get(ourl)
        origin = json.loads(r.text) # data in origin server
                
        for cmstruct in cluster:
            machine = cmstruct['machine']
            murl = urlparse.urljoin(cmstruct['url'], suffix)
            r = requests.get(murl)
            l = json.loads(r.text)    
            cmstruct[scode] = l
            
            compare_listdict(origin, l, machine)

            url = urlparse.urljoin(cmstruct['url'],'/api/profile')
            
            
    for i,cmstruct in enumerate(cluster):
        for p in cmstruct['plist']:
            if p['ci'] != i:
                continue
                
            # print "* Profile {}/{} (ci: {}) on {}".format(p['rid'], p['email'], p['ci'], cmstruct['machine'])

            purl = urlparse.urljoin(cmstruct['url'],'/api/profile/{}'.format(p['rid']))
            r = requests.get(purl)

            if r.status_code != 200:
                print "ERROR", purl, r.status_code, r.text
                return
                
            l = json.loads(r.text)    
            p['profile'] = l

            for prj in p['profile']['owner']:
                pname = prj['name']
                pid = prj['id']
                for cms2 in cluster:
                    if cmstruct == cms2:
                        continue
                    cmpproject(cmstruct, cms2, prj['id'])        

class Command(BaseCommand):
    help = 'Manage backup/restore'
    
    # trans_models = [Profile, Project, Indicator, Policy, ProjectMember]
    

    def set_rid(o):
        if o.rid:
            return False
        o.rid = o.__class__.__name__ + ':' + settings.HOSTNAME + ':' +str(o.id)
        return True


    
    def add_arguments(self,parser):                
        
        trans_group = parser.add_argument_group('Local transactions database')
        trans_group.add_argument('--drop', metavar="RID", default=False, action='store', nargs='?', const=True, help='drop transactions')        

        trans_group.add_argument('--show', metavar="RID", default=False, action='store', nargs='?', const=True, help='show transactions')        
        trans_group.add_argument('--update', metavar="RID", default=False, action='store', nargs='?', const=True, help='update ALL transactions (dangerous)')        
        trans_group.add_argument('--ciupdate', metavar="CI", default=False, action='store', type=int, nargs='?', const=True, help='update transactions for this CI')        
        trans_group.add_argument('--load', default=False, action='store_true', help='load transaction from JSON --url (can be file)')        

        trans_group.add_argument('--summary', default=False, action='store_true', help='show summary for transactions')        
        trans_group.add_argument('--dump', default=False, action='store_true', help='dump all transactions')        
        trans_group.add_argument('--recent', default=False, action='store_true', help='dump only recent transactions')        


        opts_group = parser.add_argument_group('Options')
        opts_group.add_argument('--user', metavar='EMAIL', default=None, help='User by email')
        # parser.add_argument('--sync', action='store_true', default=False, help='Sync from URL --url --timestamp')        
        opts_group.add_argument('--url', metavar='URL', default='http://charlie.okerr.com/api/sync', help='URL or filename for --load')        
        opts_group.add_argument('--force', default=False, action='store_true', help='force')        
        opts_group.add_argument('--hostname', default=None, help='simulate hostname')        
        opts_group.add_argument('--model', default=[], action='append', help='work only with this models')        
        opts_group.add_argument('--name', default=[], action='append', help='work only with this fields')        
        opts_group.add_argument('--ro', default=False, action='store_true', help='read-only mode for update')        
        opts_group.add_argument('--really', default=False, action='store_true', help='really (for dangerous things)')
        opts_group.add_argument('--remote', default=False, action='store_true', help='do remote operations if needed')
        opts_group.add_argument('--rid', default=None, help='this RID')
        opts_group.add_argument('--srid', default=None, help='this SRID')
        opts_group.add_argument('--brief', default=False, action='store_true', help='show in brief mode')
        opts_group.add_argument('--simple', default=False, action='store_true', help='show in simple mode')
        opts_group.add_argument('--skip', default=False, action='store_true', help='skip failed instances and continue')


        sync_group = parser.add_argument_group('Sync from remote server')
        sync_group.add_argument('--sync', default=None, metavar='MACHINE', help='sync from remote server')        
        sync_group.add_argument('--ssync', default=None, nargs='+', metavar=('SRID','MACHINE'), help='sync one Sector RID from remote server')        
        sync_group.add_argument('--syncmap', default=False, action='store_true', help='sync according to map')        
        sync_group.add_argument('--syncloop', default=False, action='store_true', help='syncmap in loop')        


        cl_group = parser.add_argument_group('Cluster management')
        cl_group.add_argument('--take', default=None, nargs='+', metavar=('SRID','MACHINE'), help='setci/sync one SRID from remote server')        
        cl_group.add_argument('--takeall', default=None, metavar='MACHINE', help='take all RIDs from remote machine')        

        cl_group.add_argument('--wipeusers', default=False, action='store_true', help='delete ALL users except for this CI')        

        cl_group.add_argument('--listcluster', metavar='CID', default=None, action='store', nargs='?', const=True, type=int, help='list cluster users')        
        cl_group.add_argument('--setci', metavar='CID', default=None, type=int, help='set cluster for one --user')        
        cl_group.add_argument('--buildcluster', default=False, action='store_true', help='build cluster (all users)')        
        cl_group.add_argument('--compare', metavar='URL', default=None, action='store', nargs='?', const="https://cp.okerr.com/", help='verification by comparision')        
        cl_group.add_argument('--cicheck', default=False, action='store_true', help='deep-check ci for local instances')        



        misc_group = parser.add_argument_group('Misc commands')
        misc_group.add_argument('--setrid', default=False, action='store_true', help='Update RID')        
        misc_group.add_argument('--reinit', default=False, action='store_true', help='drop and reinit transaction servers')        
        misc_group.add_argument('--reanimate', default=False, action='store_true', help='reanimate everything for --user or all')        



        old_group = parser.add_argument_group('Old commands')
        old_group.add_argument('--project', metavar='TEXTID', default=None, help='Project by textid')
        old_group.add_argument('--indicator', '-i', metavar='<IID or indicator name>', default=None, help='Indicator')
        old_group.add_argument('--touch', action='store_true', default=False, help='Touch mtime of profile/project/indicator')        
        old_group.add_argument('--backup', action='store_true', default=False, help='Sync from --timestamp')        
        old_group.add_argument('--tstamp', type=int, metavar='timestamp', default=0, help='unixtimestamp')        





        

    def rid2instance(self,rid):
        """ return instance with this rid or None """
        
        if not rid:
            return None
        
        te = TransactionEngine()
        for m in te.model_order:
            mname = m.__name__
            # print "look for {} in model {}".format(rid, mname)
            if not hasattr(m,'rid'):
                continue
            o = m.objects.filter(rid=rid).first()
            if o:
                return o
        
        return None

    def handle(self, *args, **options):
        # print "options:",options

        sync = Sync()
                                
        User = get_user_model()                
        
        te = TransactionEngine()

        if options['user']:
            try:
                user = User.objects.get(email=options['user'])
                profile = Profile.objects.get(user=user)                                    
            except ObjectDoesNotExist:
                print "No such user with email '{}'. Sorry.".format(options['user'])
                return
        else:
            user = None
            profile = None

        
        if options['reanimate']:
            if profile is None:
                for p in Profile.objects.filter(ci=myci()):
                    reanimate(p)
            else:
                reanimate(profile)
            return

        if options['compare'] is not None:
            compare(options['compare'])
            return
            
        if options['cicheck']:
            cicheck()
            return
            
        if options['ssync']:
            srid = options['ssync'][0]
            if len(options['ssync'])==2:
                machine = options['ssync'][1]
            else:
                machine = None
            ssync(srid, machine)
                    
        if options['take']:
            srid = make_srid(options['take'][0])   
                                         
            if len(options['take'])==2:
                machine = options['take'][1]
            else:
                machine = None
            take(srid, machine)
            print "Done. Do not forget to --ciupdate !"
            return

        if options['takeall']:
            machine = options['takeall']
            takeall(machine, options['hostname'])
            print "Done. Do not forget to --ciupdate !"
            return


        
        try:
            if options['buildcluster']:
                print "building cluster"
                for p in Profile.objects.all():
                    ci = p.calculate_ci()
                    print "{} - > {}".format(p,ci)
                    p.set_ci(ci, options['force'])
                    p.save()


            if options['setci'] is not None:
                if options['user']:
                    profile = Profile.objects.get(user__email = options['user'])
                    setci_local(profile, options['setci'])
                    if options['remote']:
                        setci_remote(profile.rid, options['setci'], options['force'])
                    else:
                        print "skip remote, because no --remote"
                else:
                    print "need --user"
                return
                


            if (options['listcluster'] == True) or (isinstance(options['listcluster'],int)):

                tsdict = dict()

                hostname = options['hostname']
                if not hostname:
                    hostname = settings.HOSTNAME
                try:                
                    ci = myci(hostname)                    
                    print "myci:", ci
                except ValueError:
                    print "not in cluster"
               
                print
                
                for i, mname in enumerate(settings.CLUSTER):
                                                    
                    if i==ci:
                        mestr = "[me]"
                    else:
                        mestr = ""
                    try:
                        ts = TransactionServer.objects.get(machine=mname)
                        tsurl = ts.url
                    except ObjectDoesNotExist:
                        tsurl = '[NO TS]'
                    tsdict[i]=mname
                    
                    if isinstance(options['listcluster'],bool) or options['listcluster'] == i:
                        print "machine {} {} {} {}".format(i, mname, mestr, tsurl)

                print
                if options['listcluster'] is True:
                    cid = None
                else:
                    cid = options['listcluster']
                                                
                # print "cid:",cid,type(cid)
                for p in Profile.objects.all().order_by('user__email'):
                    if p.ci == cid or cid is None:
                        print "user", p.user, p.ci, tsdict[p.ci]

            if options['syncmap']:
                TransactionServer.sync_map(ro = options['ro'], verbosity = options['verbosity'])
                return

            if options['syncloop']:
                while True:
                    s = time.time()
                    TransactionServer.sync_map(ro = options['ro'])
                    print "syncmap took {:.2f} sec".format(time.time() - s)
                    print 'syncmap loop {} Memory usage: {} (kb)'.\
                        format(os.getpid(),resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)

                    time.sleep(60)
                return



            if options['sync']:
                try:
                    tsrv = TransactionServer.objects.get(machine=options['sync'])
                except ObjectDoesNotExist:
                    print "no such machine",options['sync']
                    return
                    
                opts = None
                if options['model']:
                    if opts is None:
                        opts = dict()
                    opts['model_name'] = options['model']
                   
                if options['rid']:
                    if opts is None:
                        opts = dict()
                    opts['rid'] = options['rid']
                    
                print tsrv.sync(ro=options['ro'], opts=opts, verbosity=options['verbosity'], skip=options['skip'])
                tsrv.save()
                return

            if options['reinit']:
                TransactionServer.reinit()
                return

            if options['show'] != False:
                if options['show'] == True:
                    qs =  Transaction.objects.all()
                    for t in qs:
                        print t
                    print "# Total: {} records".format(qs.count())
                else:
                
                    if '.' in options['show']:
                        rid, name = options['show'].split('.')
                        qs = Transaction.objects.filter(rid = rid, name=name)
                    else:
                        rid = options['show']
                        name = None
                        qs = Transaction.objects.filter(rid = rid)
                    
                    print "rid:",rid
                    print "name:",name
                    for t in qs:
                        if name is None:
                            print t
                        elif t.name == name:
                            print t.value
                    print "# Total: {} records".format(qs.count())
                    
                return

                                  
            if options['dump']:
                printed = list()
                data = te.dump(0)

                lastrid = None
                dt_first = None
                dt_last = None



                for t in data:
                    # filter it
                    if options['model']:
                        if not t['model_name'] in options['model']:
                            continue

                    if options['name']:
                        if not t['name'] in options['name']:
                            continue

                    if options['rid']:
                        if t['rid'] != options['rid']:
                            continue

                    if options['srid']:
                        if t['srid'] != options['srid']:
                            continue
                    
                    if options['brief']:
                        if t['rid'] in printed:
                            continue
                        print t['rid']
                        printed.append(t['rid'])

                    elif options['simple']:
                        if lastrid is None:
                            lastrid = t['rid']
                            dt_first = t['created']
                            dt_last = t['created']
                            
                        if t['rid'] != lastrid:
                            # new RID, newline
                            print "# ",lastrid, int(time.time()) - dt_first, int(time.time()) - dt_last
                            lastrid = t['rid']
                            
                            dt_first = t['created'] # earliest
                            dt_last = t['created'] # laste
                            print
                            
                        if t['created'] < dt_first:
                            dt_first = t['created']
                        if t['created'] > dt_last:
                            dt_last = t['created']
                        
               
                        i = self.rid2instance(t['value'])
                        if i:
                            suffix = "({})".format(i)
                        elif t['model_name'] == 'Indicator' and t['name'] in ['updated','mtime','changed']:
                            agesec = time.time() - int(t['value'])
                            suffix = "(age: {})".format(dhms(agesec))
                        else:
                            suffix = ""
               
                        print "{} = {} {}".format(t['name'], t['value'], suffix)
                
                    else:
                        print t
                
                
                # now, print last tail
                if options['simple']:
                    if dt_first and dt_last:
                        print "# ", lastrid, int(time.time()) - dt_first, int(time.time()) - dt_last

#                print json.dumps(data, indent=4, separators=(':', ','), sort_keys=True)
                                  
            if options['drop'] != False:
                if options['drop'] == True:
                    print "drop all"
                    if options['really']:
                        qs = Transaction.objects.all()
                    else:
                        print "You are not really."
                        return
                else:
                    print "drop rid",options['drop']
                    qs = Transaction.objects.filter(rid = options['drop'])                
                r = qs.delete()
                print "Deleted",r[0],"records"
                return

            if options['recent']:
                t = Transaction.objects.latest('created')
                c = t.created - datetime.timedelta(0,3) 
                for t in Transaction.objects.filter(created__gte=c).order_by('created'):
                    print t
                return


            if options['summary']:

                print json.dumps(TransactionEngine.summary(Profile),
                    indent=4, separators=(',',': '), sort_keys=True)
                return    
            
                sum_verify = 0
                
                for srid in Transaction.objects.values('srid').annotate(c = Count(1)):
                    mc_verify = 0
                    
                    p = Profile.objects.get(rid = srid['srid'])
                    mc = dict()
                    # model records
                    for mrec in Transaction.objects.filter(srid=srid['srid']).values('model_name').annotate(c = Count(1)):
                        # print "mrec :",mrec                        
                        c = Transaction.objects.filter(srid=srid['srid'], model_name = mrec['model_name']).values('rid').annotate(c = Count(1)).count()
                        # print "c:",c 
                        
                        mc[mrec['model_name']] = { 'r': c, 't': mrec['c'] , 'a': mrec['c'] / c}
                        mc_verify += mrec['c']
                        sum_verify += mrec['c']

                    if mc_verify == srid['c']:
                        vmsg = "OK"
                    else:
                        vmsg = "verification FAIL ({} != {})".format(mc_verify, srid['c']) 
                                            
                    print "{srid} {profile} ({c}) {vmsg}".format(srid = srid['srid'], profile=p, c = srid['c'], vmsg=vmsg)
                    for mname in mc:
                        print "    {} {}*{}={}".format(mname, mc[mname]['r'], mc[mname]['a'], mc[mname]['t']) 
                   
                    print 
                print "---"
                tcount = Transaction.objects.count()
                if tcount == sum_verify:
                    print "summary verification OK ({} = {})".format(sum_verify, Transaction.objects.count())
                else:
                    print "summary verification FAIL ({} != {})".format(sum_verify, Transaction.objects.count())
                    
                return


            if options['wipeusers']:
                if not options['really']:
                    print "Wipe users? Really??"
                    return
                    
                c1 = counts(te)
                hostname = options['hostname']
                if not hostname:
                    hostname = settings.HOSTNAME
                try:                
                    ci = myci(hostname)                    
                    if ci is None:
                        print "no ci for hostname",hostname
                        return
                    print "myci:", ci
                    
                except ValueError:
                    print "not in cluster"
                    return
                
                for p in Profile.objects.all():
                    if p.ci == ci:
                        print "keep profile",p
                    else:
                        print "delete profile",p,"ci {} != {}".format(p.ci, ci)
                        p.user.delete()
                        p.delete()
                print("Done")
                c2 = counts(te)

                for k in c1.keys():
                    print "{}: {} => {}".format(k,c1[k],c2[k])                    



            if options['ciupdate'] != False:
                if options['ciupdate'] == True:
                    hostname = options['hostname']
                    if not hostname:
                        hostname = settings.HOSTNAME
                    try:                
                        ci = myci(hostname)                    
                        print "myci:", ci
                    except ValueError:
                        print "not in cluster"
                        return
                else:
                    ci = options['ciupdate']
                
                if ci is None:
                    print "dont know ci for --ciupdate"
                    return
                print "update for ci",ci
                start = time.time()                                                            
                for m in te.model_order:
                    mname = m.__name__                    
                    if len(options['model'])>0 and not mname in options['model']:
                        print "skip model",mname
                        continue
                
                    mstart = time.time()
                    c = te.update_model(m,ro = options['ro'], ci=ci)
                    mstop = time.time()
                    print "# {:.2f}s model {} ({} transactions)".format(mstop-mstart, mname, c)
                stop = time.time()
                print "# {}s Done".format(stop-start)
            

            if options['update'] != False:
                if options['update'] == True:
                    if options['really'] == False:
                        print "Update all (not --ciupdate)? You're not really."
                        return

                    start = time.time()                                                            
                    for m in te.model_order:
                        mname = m.__name__                    
                        if len(options['model'])>0 and not mname in options['model']:
                            print "skip model",mname
                            continue
                    
                        mstart = time.time()
                        te.update_model(m,ro = options['ro'])
                        mstop = time.time()
                        print "# {:.2f}s model {}".format(mstop-mstart, mname)
                    stop = time.time()
                    print "# {}s Done".format(stop-start)
                else:
                    rid = options['update']
                    print "update rid", rid
                    for model in te.model_order:
                        try:
                            o = model.objects.get(rid=rid)
                            print "force update",model.__name__,o
                            te = TransactionEngine()
                            te.update_instance(o)
                            return
                        except ObjectDoesNotExist:
                            pass
                            
                    
                return
                
            if options['load']:
                print "load"
                if options['url'].startswith('http'):            
                    url = options['url']+'/'+str(options['tstamp'])
                    print "url:",url
                    print "load from URL {}".format(url)
                    r = requests.get(url)
                    if r.status_code != 200:
                        print "ERROR! Couldn't get from {} (HTTP code: {})".format(url,r.status_code)
                        return
                    data = json.loads(r.text)
                else:
                    # read from file
                    print "load from file",options['url']
                    with open(options['url']) as data_file:
                        data = json.load(data_file) 
                    print "data:",len(data),"records"
                
                print te.load(data, options['model'], ro=options['ro'])
            
            if options['setrid']:
                for mdl in te.model_order:
                    print "set rid for model", mdl
                    for o in mdl.objects.filter(Q(rid__isnull=True) | Q(rid='')):
                        print "set rid for",o
                        if self.set_rid(o):
                            o.save()

        except TransactionError as e:
            print "EXC:",str(e)


        if options['user']:
            try:
                u = User.objects.get(email=options['user'])
                profile = Profile.objects.get(user=u)

                if options['touch']:
                    profile.touch()
                    profile.save()
            
                print profile,profile.mtime, dt2unixtime(profile.mtime)
                        
            except ObjectDoesNotExist:
                print "No such user with email '{}'. Sorry.".format(options['user'])
                return
        
        elif options['project']:
            p = Project.get_by_textid(options['project'])

            if p:
            
                if options['indicator']:
                    print "indicator: {}".format(options['indicator'])
                    try:
                        i = p.geti(options['indicator'])
                        print "#{} {}".format(i.id,str(i))
                        if options['touch']:
                            i.touch()
                            i.save()
                    except ObjectDoesNotExist:
                        print "no indicator {} in project #{}:{} (tid: {})".format(
                            options['indicator'],
                            p.id,
                            p.name,
                            options['project']
                            )
                            
                else:                       
                    if options['touch']:
                        p.touch()
                        p.save()
                    print p,p.mtime, dt2unixtime(p.mtime)                
            else:
                print "No such project with textid {}".format(options['project'])        
        
        elif options['backup']:
            tstamp = unixtime2dt(options['tstamp'])
            print json.dumps(sync.backup(tstamp), indent=4, separators=(',',': '), sort_keys=True)   
            
            # print json.dumps(Profile.syncbackup_all(tstamp), indent=4, separators=(',',': '), sort_keys=True)
        elif False and options['sync']:
            print "sync"
            if options['url'].startswith('http'):            
                url = options['url']+'/'+str(options['tstamp'])
                print "url:",url
                print "sync from URL {}".format(url)
                r = requests.get(url)
                if r.status_code != 200:
                    print "ERROR! Couldn't get from {} (HTTP code: {})".format(url,r.status_code)
                    return
                data = json.loads(r.text)
            else:
                # read from file
                with open(options['url']) as data_file:
                    data = json.load(data_file) 

            sync.restore(data)
                
            
        
