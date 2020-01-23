# transaction models
from django.db import models, IntegrityError
from django.conf import settings
import django.utils.timezone
from django.core.exceptions import FieldDoesNotExist, ObjectDoesNotExist
from django.forms.models import model_to_dict
from django.db.models import Q, Count
# from django.db import 
from django.db import IntegrityError


import okerrui.models
import json
import time
import requests
import urllib.parse
from operator import itemgetter

import myutils
#
# 


def myci(hostname = None):
    if hostname is None:
        hostname = settings.HOSTNAME
    try:
        return settings.CLUSTER.index(hostname)
    except ValueError:
        return None


# utility functions, no need to use outside of module

def list2dict(l, hier):

    def put(out, li, path):
        for pn, p in enumerate(path):
            try:
                out = out[p]
            except KeyError as e:
                out[p] = dict()
                out = out[p]
        out[li['name']] = li['value']
            

    out = dict()
    keyfield = hier[0]
    
    for li in l:
        path = list()
        for h in hier:
            path.append(li[h])
            # li.pop(h)            
        put(out, li, path)
        
    return out
    
    


def godeep(*args):
    path = list()
    
    o = args[0]
    
    for a in args[1:]:
        if isinstance(a, str):
            path.append(a)
        elif isinstance(a, tuple):
            for aa in a:
                path.append(aa)
        else:
            print("godeep: type {} unsupported!".format(type(a)))
    
    # print "godeep: from {}/{} path: {}".format(type(o),o, path)
    for fname in path:
        o = getattr(o, fname)
    return o



class TransactionError(Exception):
    pass

class TransactionWarning(TransactionError):
    pass



class TransactionServer(models.Model):
    lastupdate = models.DateTimeField(default = myutils.unixtime2dt(0))
    machine = models.CharField(max_length=100, default='')
    url = models.CharField(max_length=100, default='')
    netprocess = models.BooleanField(default=True)
    private = models.BooleanField(default=False)

    srv = [
        { 
            'machine': 'alpha',
            'url': 'https://alpha.okerr.com/',
            'netprocess': True,
            'private': False
        },
        { 
            'machine': 'braconnier',
            'url': 'http://localhost:8000/',
            'netprocess': False,
            'private': True
        },
        {
            'machine': 'charlie',
            'url': 'https://charlie.okerr.com/',
            'netprocess': True,
            'private': False
        },
    ]

    def __unicode__(self):
        return "{} {} {}".format(self.machine,self.url,self.lastupdate)


    # transactionserver.action_url
    def action_url(self, action, *args):
                
        if action == 'sync':
            urltpl = urllib.parse.urljoin(self.url, '/api/sync/{}')
        elif action == 'sdump':
            urltpl = urllib.parse.urljoin(self.url, '/api/sdump/{}')
        elif action == 'setci':
            urltpl = urllib.parse.urljoin(self.url, '/api/setci')
        elif action == 'fsync':
            url = '/api/fsync'
            for a,v in args[0].iteritems():
                if isinstance(v,list):
                    for vv in v:
                        url += '/{}={}'.format(a,vv)
                else:
                    url +='/{}={}'.format(a,v)
            url = urllib.parse.urljoin(self.url, url)
            return url
        else:
            print("unknown action",repr(action))
            return None
        
        # print "tpl: {} args: {}".format(urltpl, list(args))
        url = urltpl.format(*args)        
        return url
                

    # transactionserver.ciserver    
    @staticmethod
    def ciserver(ci=None):
    
        if ci is None:
            ci = myci()
        
        sname = settings.CLUSTER[ci]
        tsrv = TransactionServer.objects.get(machine = sname)
        return tsrv
        
            
    # transactionserver.reinit    
    @classmethod
    def reinit(cls):
        print("deleted", cls.objects.all().delete())
        dt = myutils.unixtime2dt(0)
        for srv in cls.srv:        
            ts = TransactionServer(machine = srv['machine'], url = srv['url'], private = srv['private'], netprocess = srv['netprocess'], lastupdate = dt)
            print(ts)
            ts.save()

    # transactionserver.sync_map
    @classmethod
    def sync_map(cls, ro=False, verbosity=1):
        # print "sync map",settings.HOSTNAME
        out = dict()
        if ro:
            print("read-only")
        if settings.HOSTNAME in settings.SYNC_MAP:
            for machine in settings.SYNC_MAP[settings.HOSTNAME]:
                print("sync",settings.HOSTNAME,"from", machine)
                tsrv = cls.objects.get(machine=machine)
                msg = tsrv.sync(ro=ro, verbosity=verbosity)
                out[tsrv.machine] = msg
                tsrv.save()
        return out

    # transactionserver.cron
    @classmethod
    def cron(cls):
        # return cls.sync_map()
        return None

    # transactionserver.sync
    def sync(self, opts=None, ro=False, verbosity=1, skip=False):
        
        te = TransactionEngine()
        
        if opts is None:
            ls = myutils.dt2unixtime(self.lastupdate)    
            url = self.action_url('sync', ls)
        else:
            url = self.action_url('fsync', opts)

        if verbosity>=2:
            print("URL:",url)
                                
        r = requests.get(url)
        
        if r.status_code != 200:
            print("ERROR! Couldn't get from {} (HTTP code: {})".format(url,r.status_code))
            return
        data = json.loads(r.text)
        
        last = 0
        for t in data:
            if t['created']>last:
                last = t['created']

        print("got",len(data),"transactions from",self.machine)

        #with django.db.transaction.atomic():
        msg = te.load(data, ro=ro, verbosity=verbosity, skip=skip)
        
        if opts is None and not ro:
            # update lastupdate only in real run
            self.lastupdate = myutils.unixtime2dt(last)
        
        return msg

    # transactionserver.ssync   
    def ssync(self, srid, ro=False, verbose=False):
        """
            sync only one SRID (profile)
        """
        
        te = TransactionEngine()
        
        url = self.action_url('sdump', srid)
        
        r = requests.get(url)
        if r.status_code != 200:
            print("ERROR! Couldn't get from {} (HTTP code: {})".format(url,r.status_code))
            return
        data = json.loads(r.text)
        
        print("got",len(data),"transactions from",self.machine)
        with django.db.transaction.atomic():
            te.load(data, ro=ro)


    # transactionserver.setci        
    def setci(self, ci, email):
        data = { 'ci': ci, 'email': email}
        url = self.action_url('setci', email)
        r = requests.post(url, data)
        if r.status_code != 200:
            print("Error! status: {} url: {}".format(r.status_code, url))
        else:
            print("remote:",r.text)

    # transactionserver.take        
    def take(self, srid):    
        ci = myci()
        self.setci(ci, srid)
        self.ssync(srid)
    
    

class UnusedTransactionEngine():
    modelconf = None
    models = None       

    model_order = None

    delayed_load = None
    delayed_transactions = None

    reanimate = None

    parents = None
    
    hier = ['Profile', 'Project', 'Indicator']
    
    ci_models = dict()
    
    def __init__(self):
    
        self.model_order = list()
        self.delayed_load = list()
        self.reanimate = list()
        
        self.parents = dict()
        self.delayed_transactions = dict()
        self.models = dict()
        self.modelconf = dict()
                
        self.set_model(okerrui.models.Profile,'user',('ignore',))

        self.set_model(okerrui.models.Membership,'profile',('trans','rid'))
        self.set_model(okerrui.models.Membership,'group',('trans','name'))
        self.set_parent(okerrui.models.Membership,'profile')


        self.set_model(okerrui.models.ProfileArg,'profile',('trans','rid'))
        self.set_model(okerrui.models.ProfileArg,'group',('trans','name'))
        self.set_parent(okerrui.models.ProfileArg,'profile')


        self.set_model(okerrui.models.Project,'owner',('trans','profile','rid'))
        self.set_parent(okerrui.models.Project,'owner')


        self.set_model(okerrui.models.ProjectMember,'project',('trans','rid'))
        # self.set_model(okerrui.models.ProjectMember,'user',('trans','profile','rid'))
        self.set_parent(okerrui.models.ProjectMember,'project')


        self.set_model(okerrui.models.ProjectInvite,'project',('trans','rid'))
        self.set_parent(okerrui.models.ProjectInvite,'project')

        self.set_model(okerrui.models.Policy,'project',('trans','rid'))
        self.set_parent(okerrui.models.Policy,'project')


        self.set_model(okerrui.models.Indicator,'policy',('trans','rid'))
        self.set_model(okerrui.models.Indicator,'project',('trans','rid'))
        self.set_model(okerrui.models.Indicator,'cm',('ignore',))
        self.set_parent(okerrui.models.Indicator,'project')
        

        for ign_field in ['scheduled','expected','lockat','lockpid','retry', 'trans_last_sync', 'trans_last_update']:
            self.set_model(okerrui.models.Indicator,ign_field,('ignore',))

        self.model_order = [
            okerrui.models.Profile, 
            okerrui.models.Membership,             
            okerrui.models.ProfileArg,             
            okerrui.models.Project, 
            okerrui.models.ProjectMember,
            okerrui.models.ProjectInvite,
            okerrui.models.Policy,
            okerrui.models.Indicator
            ]

        ### self.delayed_load.append(('Project','defpolicy','Policy'))
            
        self.ci_models['Membership'] = 'profile__ci'
        self.ci_models['ProfileArg'] = 'profile__ci'
        self.ci_models['ProjectMember'] = 'project__ci'
        self.ci_models['Policy'] = 'project__ci'
        self.ci_models['ProjectInvite'] = 'project__ci'                
        
    def set_rid(self,o):
        if o.rid:
            return False
        o.rid = o.__class__.__name__ + ':' + settings.HOSTNAME + ':' +str(o.id)
        return True
        
    def set_rid_model(self,m):
        # print "set rid for model", m.__name__
        for o in m.objects.filter(Q(rid__isnull=True) | Q(rid='')):
            print("set rid for", o)
            if self.set_rid(o):
                o.save()

    
                
    def set_model(self, m, fname, handle):
        mname = m.__name__
        if not mname in self.modelconf:
            self.modelconf[mname] = dict()
        
        self.modelconf[mname][fname] = handle
    
    def set_parent(self, cls, fname):
        self.parents[cls.__name__] = fname                    
    
    def learn_model(self, m):
        mname = m.__name__

        if mname in self.models:
            return

        md = dict()
        try:
            mdf=dict(self.modelconf[mname])                                
        
        except KeyError:
            mdf = dict()
        
        md['fields']=mdf 
        
        
        md['postdump'] = getattr(m,'transaction_postdump',None)
        md['postload'] = getattr(m,'transaction_postload',None)
        md['reanimate'] = getattr(m,'transaction_reanimate',None)


        for f in m._meta.get_fields():
                
            if f.name == 'id':
                continue
            
            if f.name in mdf:
                # pre-filled from modelconf
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
                            raise TransactionError("!!! {}.{} is UNKNOWN FK to {}:".format(mname,f.name,relname))
                    else:
                        raise TransactionError("!!! {}.{} is FK to {} but no modelconf".format(mname,f.name,relname))

            else:
                # data field
                if isinstance(f,models.fields.DateTimeField):
                    mdf[f.name] = ('DT',)
                elif isinstance(f,models.fields.IntegerField):
                    mdf[f.name] = ('INT',)
                elif isinstance(f,models.fields.BooleanField):
                    mdf[f.name] = ('BOOL',)
                else:
                    mdf[f.name] = None               
    
        self.models[mname]=md
        # print "LEARNED model {}".format(mname)

    # transactionengine.t2dict
    def t2dict(self,rid):
        """
        get all transactions for this rid as dict
        """
        td = dict()
        for t in Transaction.objects.filter(rid = rid):
            td[t.name] = t.value
        return td

    # transactionengine.postfunc
    # used from o2dict when --update
    #
    def postfunc(self, func, o, f):
        model = o.__class__
        mname = model.__name__

        if func[0] == 'DT':
            val = getattr(o,f,None)
            if val is None:
                return None
            else:
                return myutils.dt2unixtime(getattr(o,f,None))

        if func[0] in ['INT']:
            val = getattr(o,f,None)
            if val is None:
                return None
            else:
                return unicode(val)

        if func[0] in ['BOOL']:
            val = getattr(o,f,None)
            if val is None:
                return None
            else:
                return json.dumps(val)       
       
       
        if func[0] == 'trans':
            # print "postfunc {} {} o:{} f: {}".format(func,mname,o,f)
            route = self.models[mname]['fields'][f]
            method = route[0]
            if method == 'trans':
                v = getattr(o,f,None)
                for ff in route[1:]:
                    # print "{} > {}".format(v,ff,None)
                    v = getattr(v,ff)
                # print "final:",v
                return v

        return None

    # transactionengine.o2dict        
    def o2dict(self, o):
        """
        get all fields as dict 
        """       

        # learn model
        self.learn_model(o.__class__)

        mname = o.__class__.__name__
        minfo = self.models[mname]
        d = dict()
                
        for f, postfunc in minfo['fields'].iteritems():
            if postfunc:
                if postfunc[0]!='ignore':
                    val = self.postfunc(postfunc, o, f)
                    # print "postfunc {}.{} = {}".format(mname, f, val) 
                    d[f] = val
            else:
                val = getattr(o,f,None)
                d[f] = val

        # apply postdump function if needed
        if minfo['postdump']:            
            minfo['postdump'](o,d)
        
        # quick-check, all values must be scalar
        for k,v in d.iteritems():
            # print k,v,type(v)
            if not isinstance(v,(unicode,str,type(None))): 
                # print "BAD TYPE {}.{} - {}".format(mname, k, type(v))
                d[k] = json.dumps(v,sort_keys=True)
    
        # print json.dumps(d,indent=4)
        return d        



    # transactionengine.get_parent
    def get_parent(self,o,prid=False):
    
        # print "get_parent for {}/{} (prid: {})".format(type(o),o, prid)
    
        def get_priority(o, name, handle):
            oo = godeep(o,name,handle[:-1])
            oname = oo.__class__.__name__
            
            try:
                i = self.hier.index(oname)
                # print "index for {} is {} ({})".format(oname, i, self.hier)
                return i
            except ValueError:
                # print "not found {} in {} {}".format(oname, self.hier, handle)
                return 100
            
            
        mname = o.__class__.__name__
        
        if self.hier[0] == mname: # no parent for root model
            return None
        
        mc = self.modelconf[mname]
        prio = {}
        # print mc
        for oname in mc.keys():
            if mc[oname][0] == 'trans':
                prio[oname] = get_priority(o,oname, mc[oname][1:])
        
        pname = min(prio, key = prio.get) 
        if prio[pname]>= 100:
            print("WARN: prio[{}] = {}".format(pname, prio[pname]))
        
        
        if prid:        
            # parent rid
            parent = godeep(o, pname, mc[pname][1:])
        else:
            # parent itself            
            parent = godeep(o, pname, mc[pname][1:-1])        
        return parent

    # transactionengine.get_prid
    def get_prid(self,o):    
        return self.get_parent(o, prid=True)

        
    # transactionengine.get_srid
    def get_srid(self,o):
        mname = o.__class__.__name__
        # print "get sector rid for {} {} {}".format(mname, o.rid, o)
        smname = self.hier[0]
        
        # print "smname:",smname
        while o.__class__.__name__ != smname:
            # print "o:",type(o),o
            o = self.get_parent(o)
        # print "o: {} rid: {}".format(o, o.rid)
        return o.rid 
    

    # transactionengine.update_instalce
    def update_instance(self, o, ntl = None):
        """
            check/update transactions for object o
            if ntl is None - save created transactions. 
            if ntl - append to ntl            
        """
        mname = o.__class__.__name__
                        
        def mktrans(mname, rid, prid, srid, k,v, ntl):

            # get old transaction
            try:
                old = Transaction.objects.get(rid=rid, prid=prid, srid=srid, name=k)

                old.value = v
                old.save()
                        
            except ObjectDoesNotExist:                
                transaction = Transaction(
                    machine = settings.HOSTNAME, 
                    model_name = mname, 
                    rid = rid, 
                    prid=prid, 
                    srid=srid,
                    name=k, 
                    value=v)
                if ntl is None:
                    transaction.save()
                else:
                    ntl.append(transaction)

    
        rid = o.rid
        
        #print "call get_prid for {}: {}".format(type(o), o)
        prid = self.get_prid(o)
        srid = self.get_srid(o)
        
        # prid = None
        # srid = None

        #print "prid: {} srid: {}".format(prid, srid)

        if rid is None or rid=='':
            raise TransactionError('update_instance: object ({}) {} has empty rid ({})'.format(mname, str(o), repr(rid)))

        #print "update ({}): {}".format(rid, o)
        td = self.t2dict(rid)        
        od = self.o2dict(o)



        # maybe values are changed?
        for k,v in td.iteritems():
            if k=='rid':
                continue
            
            if od[k] == v:
                continue
                
            # print "{} KEY {} changed {} > {}".format(rid,k,repr(v),repr(od[k]))
            mktrans(mname, rid, prid, srid, k, od[k], ntl)

        # maybe no transaction at all?
        for k,v in od.iteritems():
            if k=='rid':
                continue
                
            if k in td:
                continue
            # print "{} NEW KEY {} = {}".format(rid,k,repr(v))
            mktrans(mname, rid, prid, srid, k, v, ntl)



    # transactionengine.update_model
    def update_model(self, m, ro=False, ci=None):
        mname = m.__name__
        print("update model {}".format(mname))

        c=0

        if ro:
            print("read-only")
            return 
                
        # learn model
        self.learn_model(m)
        
        self.set_rid_model(m)
        
        
        fkfields = [ f for f,v in self.models[mname]['fields'].iteritems() if v is not None and v[0] == 'trans' ]


        # if ci is set, update only proper objects (with this ci)
        if ci is None:
            # all values
            qs = m.objects.select_related(*fkfields).all()
        else:
            if mname in self.ci_models:
                kwargs = dict()
                kwargs[self.ci_models[mname]] = ci
                qs = m.objects.select_related(*fkfields).filter(**kwargs)
            elif hasattr(m, 'ci'):
                qs = m.objects.select_related(*fkfields).filter(ci=ci)
            else:
                print("ERROR model",mname,"has no CI and not in ci_models")
                
        ntl = list()    # new transactions list      
        lastsave=time.time() 
        for o in qs:
            # oldlen = len(ntl)            
            self.update_instance(o,ntl)
            # print "+ {} transactions".format(len(ntl) - oldlen)
            
            if len(ntl)>1000:
                print("save ntl {} ({}) {:.2f}s".format(mname, len(ntl), time.time() - lastsave))
                lastsave = time.time()
                c += len(ntl)
                Transaction.objects.bulk_create(ntl)
                ntl=list()
                
    
        if len(ntl)>0:
            print("save ntl {} ({})".format(mname, len(ntl)))
            c += len(ntl)
            Transaction.objects.bulk_create(ntl)
            print("saved...")
        return c

    # transactionengine.fdump flexible dump
    def fdump(self, opts):
        print("te.fdump")
        data = list() 
        kw = dict()

        qs = Transaction.objects.all()
        
        if 'tstamp' in opts:
            dt = myutils.unixtime2dt(opts['tstamp'])
            qs = qs.filter(created__gre=dt)

        for f in ['machine','model_name','rid','prid','srid','name','value']:
            if not f in opts:
                continue
            if isinstance(opts[f],list):            
                kw[f+'__in'] = opts[f]
            else:
                kw[f] = opts[f]
    
        qs = qs.filter(**kw)
    
        for t in qs:
            data.append(t.data())
        return data


    # transactionengine.dump
    def dump(self, timestamp=None, srid=None):
        data = list()
        
        if srid is not None:
            qs = Transaction.objects.filter(srid=srid)
        elif timestamp is not None:
            dt = myutils.unixtime2dt(timestamp)
            qs = Transaction.objects.filter(created__gte=dt)
        else:
            qs = Transaction.objects.all()
        
        for t in qs:
            data.append(t.data())

        #   hier = ['srid','model_name','rid']            
        # return list2dict(data, hier)
        return data
        


    # transactionengine.load_transaction
    def load_transaction(self, o, t, fmethod=None):
    
        def trans(o, fmethod, name,value):
            mname = o.__class__.__name__
            # print "TRANS {} {} : {} ({}={})".format(mname, o, fmethod, name, value)

            kwargs = dict()
            kwargs['__'.join(fmethod[1:])] = value
            
            try:
                rel_o = o._meta.get_field(name).related_model.objects.get(**kwargs)
            except ObjectDoesNotExist as e:
                raise TransactionWarning("{} {} {}={} EXCEPTION: {}".format(mname, fmethod, name, value, str(e)))
            
            return rel_o
            
            
        if isinstance(fmethod,tuple):
            if fmethod[0] == 'DT':
                # print "DT {} = {}".format(t['name'],repr(t['value']))
                if t['value'] is None:
                    setattr(o, t['name'],None)
                else:
                    setattr(o,t['name'],myutils.unixtime2dt(int(t['value'])))
            elif fmethod[0] == 'INT':
                setattr(o,t['name'],int(t['value']))
            elif fmethod[0] == 'BOOL':
                try:
                    val = json.loads(t['value'])
                except ValueError as e:
                    print("json decode error. value: {}".format(repr(t['value'])))
                setattr(o,t['name'],val)
            elif fmethod[0] == 'ignore':
                pass
            elif fmethod[0] == 'trans':
                value = trans(o,fmethod,t['name'],t['value'])
                setattr(o,t['name'], value)
            else:
                raise TransactionError('load_transaction: unknown fmethod {}'.format(repr(fmethod[0])))            
        elif fmethod is None:
            setattr(o, t['name'], t['value'])
        else:
            raise TransactionError('unknown type of field method {}'.format(repr(fmethod))) 

        # print "set {} = {} ({})".format(t['name'], getattr(o,t['name']),fmethod)



    # transactionengine.delay_transaction
    def delay_transaction(self,t,model):
        """
            put transaction to delayed list if needed (return True)
            otherwise False
        """
        name = t['name']
        mname = t['model_name']            
        for dt in self.delayed_load:
            if mname == dt[0] and name == dt[1]:
                aftermodel = dt[2]
                
                if not aftermodel in self.delayed_transactions:
                    self.delayed_transactions[aftermodel] = list()
                
                
                t['model'] = model
                self.delayed_transactions[aftermodel].append(t)
                return True
        return False



    # transactionengine.load_instance    
    def load_instance(self, model, rid, transactions, ro=False, verbosity=1, skip=False):

        mname = model.__name__
        #print self.models[mname]
        minfo = self.models[mname]
        
        
        if ro:
            print("R/O load_instance {}.{}".format(mname, rid))
        else:
            # print "load_instance {} {}".format(mname, rid)
            pass
        
        
        d = dict()

        try:
            o = model.objects.get(rid=rid)
        except ObjectDoesNotExist:
            if verbosity>1:
                print("No object with rid {} , create it".format(rid))
        
            if ro:
                # no object and read-only
                return False
            o = model()
            o.rid = rid
        else:
            pass
        

        st = sorted(transactions, key = itemgetter('created'))
        
        #print json.dumps(st,indent=4)
            
        for t in transactions:
            d[t['name']] = t['value']
            
            if ro:
                print(t['name'],"=",t['value'])
                continue
            
            # maybe delayed
            if self.delay_transaction(t, model):
                continue
            
            if t['name'] in self.models[mname]['fields']: 
                fmethod = self.models[mname]['fields'][t['name']]            
                try:
                    self.load_transaction(o, t, fmethod)
                except TransactionWarning as e:                
                    print("WARN load_instance:",str(e))
                    # cannot load because cannot resolve FK
                    return False
            else:
                # extra field? maybe postprocessing needed
                pass
        
                # apply postdump function if needed


        if minfo['postload'] and not ro:
            try:
                # can 'legally' fail here, e.g. if incomplete transactions, not all fields
                # then, no FK errors will happen, but cannot be saved
                minfo['postload'](o,d)
            except IntegrityError as e:
                if skip:
                    if verbosity>=2:
                        print("skip broken instance (postload) {}: {}".format(rid, str(e)))
                    return False
                else:
                    raise
       
        if verbosity>=2:
            print(o)
        
        if not ro:
            try:
                o.save()
            except IntegrityError as e:
                if skip:
                    if verbosity>=2:
                        print("skip broken instance {}: {}".format(rid,str(e)))
                    return False
                else:
                    raise

        if minfo['reanimate'] and not ro:
            self.reanimate.append(o)
            
        return True        
                
                        
    # transactionengine.load    
    def load(self, data, models=None, ro=False, verbosity=1, skip=False):
                
        if models is None:
            models = list()
        
        loaded = list()
    
        started = time.time()
        counters=dict()
    
        gd = dict() # grouped data
        for d in data:
            mname = d['model_name']
            if not mname in gd:
                gd[mname]=dict()
            rid = d['rid']
            if not rid in gd[mname]:
                gd[mname][rid]=list()
            gd[mname][rid].append(d)
        
        if verbosity>=2:
            print("Grouped transactions:")
            for mname in gd:
                print("  {}: {}".format(mname, len(gd[mname])))
        
        for m in self.model_order:
            mname = m.__name__
            
            # if we have non-empty models list, filter
            if len(models)>0 and not mname in models:
                continue                    
            
            self.learn_model(m)
            
            if mname in gd:                  
                if verbosity>=1:
                    print("load model", mname, "ro:",ro)
                                    
                if not mname in counters:
                    counters[mname] = 0
                
                for rid in gd[mname]:
                
                    if verbosity>=3:
                        print("RID:",rid)
                        print(json.dumps(gd[mname][rid], indent=4, sort_keys=True))
                
                    if self.load_instance(m,rid,gd[mname][rid], ro=ro, verbosity=verbosity, skip=skip):
                        counters[mname] += 1
                    else:
                        # skipped
                        sfname = 'skip:'+mname
                        if not sfname in counters:
                            counters[sfname] = 0
                        counters[sfname] += 1
            else:
                if verbosity>=2:
                    print("skip model {} (no transactions)".format(mname))


            if verbosity>=2:
                print("delayed transactions...")

            if mname in self.delayed_transactions:
                # print "run delayed transactions after",mname
                for t in self.delayed_transactions[mname]:
        
                    tmname = t['model_name']
                    tmodel = t['model']
                    o = tmodel.objects.get(rid=t['rid'])
        
                    if t['name'] in self.models[tmname]['fields']:                         
                        fmethod = self.models[tmname]['fields'][t['name']]            
                        try:
                            self.load_transaction(o, t, fmethod)
                        except TransactionWarning as e:
                            print("WARN load/delayed :", str(e))
                    else:
                        # extra field? maybe postprocessing needed
                        pass
                    o.save()
                    
        # reanimate loop
        if self.reanimate:
            print("reanimate {} instances".format(len(self.reanimate)))
        else:
            if verbosity>=2:
                print("nothing to reanimate")
        
        for o in self.reanimate:
            o.transaction_reanimate()
            o.save()
            
        # show statistics
        return "Loaded {} in {:.2f} sec".format(counters, time.time() - started)

    # transactionengine.summary    
    @staticmethod
    def summary(model):

        out = dict()
        mname = model.__name__
            
        sum_verify = 0
        
        
        status = True
        
        
        for srid in Transaction.objects.values('srid').annotate(c = Count(1)):
            sd = dict()
            sd['recount'] = 0
            sd['count'] = srid['c']
            
            p = model.objects.get(rid = srid['srid'])
            # model records
            for mrec in Transaction.objects.filter(srid=srid['srid']).values('model_name').annotate(c = Count(1)):
                # print "mrec :",mrec                        
                c = Transaction.objects.filter(srid=srid['srid'], model_name = mrec['model_name']).values('rid').annotate(c = Count(1)).count()
                # print "c:",c 
                
                # sd[mrec['model_name']] = { 'r': c, 't': mrec['c'] , 'a': mrec['c'] / c}
                sd[mrec['model_name']] = "{} {}".format(c, mrec['c'])
                                
                sd['recount'] += mrec['c']
                sum_verify += mrec['c']
                            
            if sd['recount'] == srid['c']:
                sd['status'] = True
            else:
                sd['status'] = False
                sd['err'] = "verification FAIL ({} != {})".format(mc_verify, srid['c']) 
                status = False
            
            out[srid['srid']] = sd
                                    
            #print "{srid} {profile} ({c}) {vmsg}".format(srid = srid['srid'], profile=p, c = srid['c'], vmsg=vmsg)
            #for mname in mc:
            #    print "    {} {}*{}={}".format(mname, mc[mname]['r'], mc[mname]['a'], mc[mname]['t']) 
           
            #print 
        #print "---"
        tcount = Transaction.objects.count()
        
        if sum_verify != tcount:
            status = False
        
        out['sum_verify'] = sum_verify
        out['count'] = tcount
        out['status'] = status
        
        return out
            
                                


class Transaction(models.Model):
    created = models.DateTimeField(auto_now=True, null=True, db_index=True)
    machine = models.CharField(max_length=100, default='')
    model_name = models.CharField(max_length=100, default='', db_index=True)
    rid = models.CharField(max_length=100, default=None, null=False, blank=False, db_index=True)
    prid = models.CharField(max_length=100, default=None, null=True) # rid or parent, to speed-up fetching 
    srid = models.CharField(max_length=100, default=None, null=True, db_index=True) # rid or SECTOR of parents, to speed-up fetching  (e.g. rid of project)
    name = models.CharField(max_length=100, default='')
    value = models.TextField(default='', null=True)
        
    def __unicode__(self):
        if self.value is None:
            v = None
        else:
            v = repr(self.value[:20])
        return "{} {} p:{} {} = {}".format(self.created, self.rid, self.prid, self.name, v)

    def data(self):
        """ return itself as dict """
        d = dict()
        for f in ['machine','model_name','rid','prid','srid','name','value']:
            d[f] = getattr(self,f,None)
        d['created'] = myutils.dt2unixtime(self.created)            
        return d
        

            

