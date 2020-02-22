import os
import sys
import time
import logging
import logging.handlers
import urllib.parse
import requests
import json
import traceback
from importlib import import_module

import django
from django.db import connection, models, IntegrityError
from collections import OrderedDict
from datetime import datetime,timedelta
from django.utils import timezone
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist

# from okerrui.models import Profile, ProjectTextID, ProfileArg, Group, Membership, Project, Policy, PolicySubnet, Indicator, ProjectMember, Membership, ProjectInvite, CheckMethod, CheckArg

from okerrui.cluster import RemoteServer, myci
# from transaction.models import TransactionServer

import myutils


def url2host(url):
    return urllib.parse.urlparse(url).hostname

class Impex():

    skipfields = ['mtime','rid','deleted_at','trans_last_sync','trans_last_update']

    modelconf = {
        'Profile': {
            'user': 'ignore',
            '__children': ['Membership', 'Project', 'ProfileArg', 'BonusActivation', 'Oauth2Binding'],  # ProfileArg? or reapply?
            '__addparent': ['user'],                        
        },
        'BonusActivation': {
            'user': 'parent',
            'BonusCode': 'ignore'
        },
        'Project': {
            'owner': 'parent',
            # 'jkeys': 'ignore',
            '__children': ['Policy','ProjectMember','ProjectTextID','Indicator','ProjectInvite',
                'StatusPage','DynDNSRecord','ProjectAccessKey'],
            '__prefetch': ['indicator_set',
                'indicator_set__cm','indicator_set__cm__checkarg_set',
                'indicator_set__policy','indicator_set__project','indicator_set__policy__project',
                'policy_set__policysubnet_set','projecttextid_set','projectinvite_set','projecttextid_set'],
            #'__select': ['indicator_set__policy']
        },
        'Policy': {
            '__children': ['PolicySubnet']
        },
        'PolicySubnet': {
            '__bulk': True
        },
        'ProjectTextID': {
            '__bulk': True
        },
        'ProjectMember': {
            '__bulk': True,
        },
        'Indicator': {
            'policy': 'ptrans:policy.name:Project', #!
            'cm': 'trans:cm.codename',
            'scheduled': 'ignore',
            'updated': 'ignore',
            'changed': 'ignore',
            'keypath': 'ignore',
            'origkeypath': 'ignore',
            'lockat': 'ignore',
            'lockpid': 'ignore',
            'newchange': 'ignore',
            'expected': 'ignore',
            'retry': 'ignore',            
            'lastfailmachine': 'ignore',
            '__bulk': True,
            '__children': [],
            '__deleted': 'deleted_at'
        },
        'Membership': {
            # 'group': 'trans:group.name',
            '__bulk': True,
        },
        'ProfileArg': {
            'group': 'trans:group.name',
            '__bulk': True                                    
        },
        'CheckArg': {
            'cm' :'ptrans:cm.codename'
        },
        'StatusPage': {
            '__children': ['StatusIndicator', 'StatusBlog','StatusSubscription']
        },
        'StatusIndicator': {
            'indicator': 'ptrans:indicator.name:Project'
        },                
        'DynDNSRecord': {
            '__children': ['DynDNSRecordValue']
        },
        'DynDNSRecordValue': {
            'indicator': 'ptrans:indicator.name:Project'            
        }                


    }

    
    lastcron = 0
    lastcron_big = 0
    
    def __init__(self):


        self.reanimate=list()
        self.models=dict()
        self.verbosity = 1
        
        self.reanimated = dict()
        self.processed = dict()

        self.started = time.time()

        self._bulk = dict()
        self._delayd = dict()
        
        self._options = {
            'reanimate_locked': list()
        }
               
        m = import_module('okerrui.models')
        bc = import_module('okerrui.bonuscode')
        self.all_models = [
            m.Profile, 
            m.Project,
            m.ProjectAccessKey,
            m.ProjectTextID, 
            m.ProjectInvite, 
            m.Policy, 
            m.PolicySubnet, 
            m.ProfileArg, 
            m.Indicator, 
            m.ProjectMember, 
            m.Membership, 
            m.CheckArg,
            m.StatusPage,
            m.StatusIndicator,
            m.StatusBlog,
            m.StatusSubscription,
            m.DynDNSRecord,
            m.DynDNSRecordValue,
            m.Oauth2Binding,
            bc.BonusActivation
        ]
        self.learn_all()

                    
    def learn_all(self):
        for m in self.all_models:
            self.learn(m)
    
    def bulk_save_add(self,o):
        mname = o.__class__.__name__
        if not mname in self._bulk:
            self._bulk[mname] = list()
        
        if hasattr(o,'reanimate'):
            o.reanimate()
            
        self._bulk[mname].append(o)
    
    def bulk_save(self):
        for m in self.all_models:
            mname = m.__name__
            if mname in self._bulk:
                self.vprint(3, "bulk_save {}: {} items".format(mname, len(self._bulk[mname])))
                model = self.get_model(mname)
                model.objects.bulk_create(self._bulk[mname])                
                self._bulk[mname] = list()

    def bulk_status(self):
        bs = dict()
        for mname in self._bulk.keys():
            bs[mname] = len(self._bulk[mname])
        return bs


    def get_stats(self):
        total = 0
        for mname, n in self.processed.items():
            total += n

        age = time.time() - self.started
        return "Age: {:.2f}, total processed: {} ({:.2f}/sec). saved: {}".format(        
            age, total, total/age, self.processed)
        

    def set_verbosity(self, verbosity):    
        self.verbosity = verbosity

    def vprint(self, v, msg):
        if self.verbosity >= v:
            print(msg)
        
    def get_model(self, mname):
        for model in self.all_models:
            if model.__name__ == mname:
                return model
        raise ValueError('get_model() not found model {} in all_models'.format(mname))
        

    def delete_deleted(self, rs):
        """
        delete records which exists locally, but not exists on remote server
        """
        
        userlist = rs.get_userlist()
        Profile = self.get_model('Profile')
        
        for p in Profile.objects.filter(ci = rs.get_ci()):
            if p.user.email in userlist:
                pass
            else:
                p.predelete()
                p.delete()

    def sync(self, url, overwrite=True):    

        rs = RemoteServer(url = url)

        User = get_user_model()
        Profile = self.get_model('Profile')
        
        
        ci = myci()
        rci = rs.get_ci()
        
        userlist = rs.get_userlist()            

        for email in userlist:
            if not email:
                continue
            log.info('sync user {} from {} rci: {}'.format(email, url2host(url), rci))
            self.vprint(2, 'sync user {} from {}'.format(email, url2host(url)))            
            profile = None
            
            # get local user
            try:
                profile = Profile.objects.get(user__email = email)
                                
                if profile.ci == ci and overwrite==False:
                    log.error('sync: user {} ci: {} is mine!!'.format(email, ci))
                    raise Exception('user: {} ci: {} is mine and not overwrite!'.format(email, ci))                            
            except User.DoesNotExist:
                pass
            except Profile.DoesNotExist:
                # no profile. okay. we will re-create it. it's safe - we dont have profile anyway
                pass
            
            try:
                data = rs.get_user(email)
            except requests.exceptions.RequestException as e:
                log.warning('sync error (user {} from {}): {}'.format(email, rs.name, str(e)))
                continue

            # delete this user before importing
            if profile:
                if overwrite:
                    # log.debug("ZZZ luser.delete (profile: {})".format(profile))
                    profile.predelete()
                    profile.delete()
                else:
                    # do not import this user, because it's local and not overwrite
                    continue

            #log.debug("ZZZ import data")
            self.import_data(data)

        self.delete_deleted(rs)
        #log.debug("ZZZ after delete deleted <")

    
    @classmethod
    def syncmap(cls, hostname=None):

        if hostname is None:
            hostname = settings.HOSTNAME

        if not settings.SYNC_MAP:
            # None or empty dict
            return

        if not hostname in settings.SYNC_MAP:
            log.error('No {} in SYNC_MAP'.format(hostname))
            return


        ie = Impex()
        ie.set_verbosity(0)

        for rsname in settings.SYNC_MAP[hostname]:            
            
            rs = RemoteServer(name = rsname)
            try:
                log.info('syncmap from {} {}'.format(rsname, url2host(rs.url)))
                ie.sync(rs.url)
            except Exception as e:
                log.error('syncmap exception {}: {}: {}'.format(url2host(rsname), str(e), traceback.format_exc()))



    # impex.cron
    @classmethod
    def cron(cls):

        modelcrontime = 1800 # 30min
        modelcrontime_big = 86400 # 2        
        if cls.lastcron and int(time.time()) < cls.lastcron+modelcrontime:
            # print "skip cronjob ({} < {} + {}, will run in {} seconds)".\
            #    format(int(time.time()),cls.lastcron,modelcrontime,cls.lastcron+modelcrontime-int(time.time()))
            return
                
        cls.lastcron=int(time.time())        
        cls.syncmap()

        if int(time.time()) > cls.lastcron_big+modelcrontime_big:
            if hasattr(settings,'IMPORT_PROFILE') and settings.IMPORT_PROFILE:
                User = get_user_model()
                filename = os.path.join(settings.BASE_DIR, settings.IMPORT_PATH, settings.IMPORT_PROFILE)
                with open(filename, "r") as infile:
                    data = json.load(infile)
                if data['ci'] == myci():
                    # only if we should use this user
                    try:
                        user = User.objects.get(email=data['email'])
                        # delete user if exist
                        if user.profile:
                            print(user.profile)
                            user.profile.predelete()
                            user.profile.delete()
                        else:
                            # user.delete()
                            pass
                    except User.DoesNotExist:
                        # no such user, great!
                        pass
                    ie = Impex()
                    ie.set_verbosity(0)
                    ie.import_data(data)
                    log.info("cron reimported user {}".format(data['email']))
                else:
                    # print("not our ci")
                    pass

            cls.lastcron_big = int(time.time())
        



    def get_one2one(self, m):
        out = list()
    
        for f in m._meta.get_fields():
            if f.one_to_one:
                fd=dict()
                fd['name'] = f.name
                fd['model'] = f.related_model
                out.append(fd)
        return out
    
            
    def get_fk_field_to(self, m, chm):
        """ get field name from m which points to chm """

        for f in m._meta.get_fields():
            if isinstance(f,models.ForeignKey):
                if f.related_model == chm:
                    return f.name
        return None
    
    
    def learn_children(self, m):
        """
            prepare '__children' list to find all children
        """
        
        mname = m.__name__
        out = list()

        # print "learn_children({})".format(mname)

        # modelconf for this model
        if mname in self.modelconf:
            mc = self.modelconf[mname]
        else:
            mc = dict()
    
        if not '__children' in mc:
            return out
        
        if isinstance(mc['__children'], list):
            for chname in mc['__children']:
                # print "learn child", chname
                chm = self.get_model(chname)
                                
                keyfield = self.get_fk_field_to(chm, m)
        
                if keyfield is not None:
                    
                    chstruct = {
                        'follow': None,
                        'field': keyfield,
                        'model': chname
                    }
                    # print "mname:",mname,"chname:",chname
                    setname = chname.lower()+'_set'
                    if hasattr(m,setname):
                        # print "good, {} has {}".format(m, setname)
                        chstruct['manager'] = setname
                    else:
                        raise ValueError("bad, {} has no {}".format(m, setname))
                    
                    
                    out.append(chstruct)
                    continue
                
                onemodels = self.get_one2one(m)
                for om in onemodels:
                    keyfield = self.get_fk_field_to(chm, om['model'])
                    if keyfield is not None:
                        chstruct = {
                            'follow': om['name'],
                            'field': keyfield,
                            'model': chname
                        }
                        out.append(chstruct)
        return out
    
    def learn(self, m):
        mname = m.__name__

        if mname in self.models:
            return

        # modelconf for this model
        if mname in self.modelconf:
            mc = self.modelconf[mname]
        else:
            mc = dict()


        md = dict()

        md['fields']=dict()
        
        for k in mc:
            if not k.startswith('__'):
                md['fields'][k] = mc[k]
        
        
        if '__bulk' in mc and mc['__bulk']:
            md['__bulk'] = True
        else:
            md['__bulk'] = False
            
                               
        md['__children'] = self.learn_children(m)

        if '__addparent' in mc:
            md['__addparent'] = list(mc['__addparent'])
        else:
            md['__addparent']=list()
        
        if '__prefetch' in mc:
            md['__prefetch'] = list(mc['__prefetch'])
        else:
            md['__prefetch']=list()

        if '__select' in mc:
            md['__select'] = list(mc['__select'])
        else:
            md['__select']=list()

        if '__deleted' in mc:
            md['__deleted'] = mc['__deleted']
        else:
            md['__deleted']= None

        
        # reanimate disabled temporary 
        for method in ['post_export', 'post_import', 'trans_last_update', 'trans_last_sync']:
            if getattr(m, method, None):
                md[method] = True
            else:
                md[method] = False            
        


        # learn parent field (in simple case, not one-to-one)
        for mmname, mmc in self.models.items():
            for chrec in mmc['__children']:
                if chrec['model'] == mname:
                    pm = self.get_model(mmname)
                    keyfield = self.get_fk_field_to(m, pm)
                    if keyfield:
                        md['fields'][keyfield]="parent"

        for f in m._meta.get_fields():
                
            if f.name == 'id':
                continue
            
            if f.name in md['fields']:
                # pre-filled from modelconf
                continue
            
            if f.name in self.skipfields:
                # should be skipped
                continue
                                        
            if f.is_relation:
                if isinstance(f,models.ForeignKey):
                    
                    relmodel = f.related_model
                    relname = f.related_model.__name__
                    
                    if mname in self.modelconf:
                        mc = self.modelconf[mname]
                        if f.name in mc:
                            # print "{}.{} is FK to {}: {}".format(mname,f.name,relname, mc[f.name])
                            # mdf[f.name] = 'FK'
                            pass
                        else:
                            raise ValueError("!!! {}.{} is UNKNOWN FK to {}:".format(mname,f.name,relname))
                    else:
                        raise ValueError("!!! {}.{} is FK to {} but no modelconf".format(mname,f.name,relname))
                else:
                    pass
            else:
                # data field
                if isinstance(f,models.fields.DateTimeField):
                    md['fields'][f.name] = 'DT'
                else:
                    md['fields'][f.name] = None               
    
        self.models[mname]=md
        # print "LEARNED model {}:".format(mname)
        # print json.dumps(self.models[mname], indent=4, sort_keys=True)
        # print

    
    def get_parent(self, model, fname, parents):
        mname = model.__name__
        # print "get_parent {}.{} {}".format(mname, fname, parents)
    
        f = model._meta.get_field(fname)
        rmodel = f.related_model
        rmname = rmodel.__name__
        if rmname in parents:
            return parents[rmname]
        
        # not found parent... maybe in one-to-one?
        ones = self.get_one2one(rmodel)
        for one in ones:
            omname = one['model'].__name__
            if omname in parents:
                print("FOUND")
                print(one)
                return parents[omname]
                                
        raise ValueError('get_parent({}, {}, {}) no parent {} in parents'.format(model, fname, parents, rmname))

    def get_children(self, o, chs, parents):
        mname = o.__class__.__name__
        chmname = chs['model']

        pm = self.models[mname]
        chm = self.models[chmname]
        out = list()

        # get child model
        #chm = self.get_model(chmname)

        #print "get_children for",o
        #print json.dumps(chs, indent=4)
        
        if chs['follow']:
            value = getattr(o, chs['follow'],None)
        else:
            value = o
        
        chmodel = self.get_model(chmname)
        
        kw = dict()
        kw[chs['field']] = value
        
        if 'manager' in chs:
            manager = chs['manager']
            # print "get child {} for {} {} via manager {}".format(chs['model'],mname, o, manager)                
            qs = getattr(o, manager)
        else:
            qs = chmodel.objects.filter(**kw)

        if chm['__deleted']:
            dfield = chm['__deleted']
            kw = dict()
            kw[dfield+'__isnull'] = True
            qs = qs.filter(**kw)

        if chm['__select']:
            qs = qs.select_related(*chm['__select'])


        if chm['__prefetch']:
            qs = qs.prefetch_related(*chm['__prefetch'])

            
        for chi in qs.all():
            chid = self.o2d(chi, parents) 
            out.append(chid)
            
        return out


    def d2o(self,d,model, parents=None):

        
        def backtrans(mname, fname, trans,value,parents):
            
            #print "backtrans mname: {} fname: {} trans: {} value: {} parents: {}".format(
            #    mname, fname, trans, value, parents                
            #   )
            
            if value is None:
                return None
            
            field = trans.split(':')[1].split('.')[1]
            
            f = model._meta.get_field(fname)
            rmodel = f.related_model
            
            kw = dict()
            kw[field]=value
            
            if trans.startswith('ptrans'):
                pmname = trans.split(':')[2]
                #print "pmname",pmname
                rfname = self.get_fk_field_to(rmodel, parents[pmname].__class__)
                #print "rfname:",rfname
                kw[rfname] = parents[pmname]
            
            #print "rmodel:", rmodel
            #print "backtrans rmodelget:", kw
            
            try:
                ri = rmodel.objects.get(**kw)
            except ObjectDoesNotExist as e:
                log.error('EXCEPTION {}: {}. kw: {}'.format(type(e), e, str(kw)))
            return ri

        mname = model.__name__
        
        if parents is None:
            parents = dict()

        # self.learn(model)
        o = model()

        m = self.models[mname]

        for fname, ftype in m['fields'].items():
            #print "restore field {} t:{} ({})".format(fname, ftype, d[fname] if fname in d else '--')
            if ftype is None:
                #print "Set {} = {}".format(fname, d[fname])
                
                # with this check we can add new fields
                if fname in d:
                    setattr(o,fname,d[fname])            
            elif ftype == 'ignore':
                pass
            elif ftype == 'DT':
                if fname in d:
                    val = d[fname]
                else:
                    val = None
                    
                if val is None:
                     setattr(o,fname,None)
                else:
                    setattr(o,fname,myutils.unixtime2dt(d[fname]))
            elif ftype == 'parent':
                #print "procces {}: {}.{} parents: {}".format(mname, fname, ftype, parents)
                #print json.dumps(m, indent=4)
                f = model._meta.get_field(fname)
                setattr(o,fname, self.get_parent(model, fname, parents))
            elif ftype.startswith('trans:') or ftype.startswith('ptrans:'):
                # print "{} {} {}".format(ftype, d, fname)
                setattr(o, fname, backtrans(mname, fname, ftype, d[fname], parents))
            else:
                raise ValueError("d2o: dont know how to handle ftype {} for {}.{}".format(ftype, mname, fname))

        if m['trans_last_sync']:
            o.trans_last_sync = timezone.now()


        if m['post_import']:
            # print "PI",mname
            self.vprint(3, "post_import {}: {}".format(mname,o))
            o.post_import(d)
        else:
            if m['__bulk']:
                self.bulk_save_add(o)
            else:
                # print "SAVE",mname,o
                o.save()
        
        if not mname in self.processed:
            self.processed[mname] = 1
        else:
            self.processed[mname] += 1
        
        #if m['reanimate']:
        #    self.reanimate.append(o)
        
        chparents = dict(parents)
        if mname in chparents:
            raise ValueError
        chparents[mname] = o

        # addparent
        for pfield in m['__addparent']:
            p = getattr(o, pfield)
            pmname = p.__class__.__name__
            if pmname in chparents:
                raise ValueError
            chparents[pmname] = p

                
        for chs in m['__children']:
            # print "Process children structure:",json.dumps(chs, indent=4)
            chmname = chs['model']
            chm = self.get_model(chmname)
            
            if chmname in d:
                for chres in d[chmname]:
                    # print chres
                    # self.d2o(chres, chm, chparents)
                    self.delay_d2o(chmname, chres, chparents)


    def delay_d2o(self, mname, res, parents=None):
        self.vprint(3, "delay {}".format(mname))
        if not mname in self._delayd:
            self._delayd[mname]=list()
    
        ds = dict()
        if isinstance(res,list):
            ds['res'] = res
        else:
            ds['res'] = [res]
            
        if parents is None:
            parents = dict()
        else:
            parents = dict(parents)
        ds['parents'] = parents
    
        self._delayd[mname].append(ds)


    def delayed_run1(self):
        for m in self.all_models:
            mname = m.__name__
            if mname in self._delayd:
                #print "post-process {}".format(mname)
                for ds in self._delayd[mname]:
                    parents = ds['parents']
                    res = ds['res']
                    for r in res:
                        self.d2o(r, m, parents)
                del self._delayd[mname]
                # print "bulk_status: {}".format(self.bulk_status())
                return


    def delayed_run(self):

        while True:
            c=0
            for mname in self._delayd.keys():
                #print ".. {}: {}".format(mname, len(self._delayd[mname]))
                c += len(self._delayd[mname])
            #print "count:",c
            if c == 0:
                return
            self.delayed_run1()
            self.bulk_save()

    def o2d(self,o, parents=None):
        mname = o.__class__.__name__
        #d = dict()
        d = OrderedDict()
        # self.learn(o.__class__)
        m = self.models[mname]

        def trans(o,trans):
        
            for step in trans.split(':')[1].split('.'):
                if o is None:
                    return None
                o = getattr(o,step)
            return o

        self.vprint(2,u'.. o2d {}: {}'.format(mname, o))


        if parents is None:
            parents = dict()
                
        for fname, ftype in m['fields'].items():
            #print "  {} = {}".format(fname, ftype)
            if ftype is None:
                d[fname] = getattr(o,fname,None)
            elif ftype == 'ignore':
                # if ignore, just skip it
                pass
            elif ftype == 'DT':
                val = getattr(o,fname,None)
                if val is None:
                    d[fname] = None
                else:
                    d[fname] = myutils.dt2unixtime(getattr(o,fname,None))
            elif ftype == 'parent':
                val = getattr(o, fname, None)
                valmname = val.__class__.__name__
                if val is None or parents[valmname] != val:
                    raise ValueError("o2d: not found field {} = {} in parents: {}".format(fname,val,parents))
            elif ftype.startswith('trans:') or ftype.startswith('ptrans:'):
                d[fname]=trans(o,ftype)
            else:
                raise ValueError("o2d: dont know how to process fname:{} ftype:{}".format(fname,ftype))

        # post export
        if m['post_export']:
            self.vprint(2, "post_export {}".format(mname))
            o.post_export(d)
        
        chparents = dict(parents)
        
        # addparent
        for pfield in m['__addparent']:
            p = getattr(o, pfield)
            pmname = p.__class__.__name__
            if pmname in chparents:
                raise ValueError
            chparents[pmname] = p
        
        if mname in chparents:
            raise ValueError
        chparents[mname] = o
        
        # process children
        for ch in m['__children']:
            chmodel = ch['model']
            # print "process children model {} > {}".format(mname, chmodel)
            d[chmodel] = self.get_children(o, ch, chparents)

        if m['trans_last_update']:
            o.trans_last_update = timezone.now()

        if not mname in self.processed:
            self.processed[mname] = 1
        else:
            self.processed[mname] += 1

        # o.save()
        return d
         
    def export_data(self, o):
        mname = o.__class__.__name__
        self.vprint(1,'export data for {}'.format(o))
        d = self.o2d(o)
        # self.bulk_save()
        return d

    def preimport_cleanup(self, data):
        # delete user/profile before import
        email = data['email']
        Profile = self.get_model('Profile')
        try:
            p = Profile.objects.get(user__email=email)
            p.predelete()
            p.delete()
        except Profile.DoesNotExist:
            # nothing to no. no user -> no need to cleanup
            pass

    def import_data(self,data):


        self.delay_d2o('Profile', data)
        self.delayed_run()
        # load
        # o = self.d2o(data, Profile)

        # reanimate
        if self.reanimate:
            self.vprint(1, "reanimate {} instances".format(len(self.reanimate)))
            for o in self.reanimate:
                self.vprint(1,"reanimate {}".format(o))
                mname = o.__class__.__name__
                o.reanimate()
                o.save()
                if not mname in self.reanimated:
                    self.reanimated[mname] = 1
                else:
                    self.reanimated[mname] += 1
            self.vprint(1, "reanimated: {}".format(self.reanimated))

        # bulk save
        # saves also reanimated instances!

        # self.bulk_save()


# main
# django.setup()
log = logging.getLogger('okerr')                



