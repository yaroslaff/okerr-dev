from django.db import models
from django.conf import settings
from django.db.models import Q
from django.db.models.base import ModelBase
from django.core.exceptions import FieldDoesNotExist, ObjectDoesNotExist
from django.apps import apps

import json
import time

import okerrui.models
import myutils


class SyncException(Exception):
    pass

# model record instance list. list of 
class RecList:
    def __init__(self):
        self.d = dict()

    def append(self,mname, data):
        if not mname in self.d:
            self.d[mname]=list()
        self.d[mname].append(data)

    def dump(self):
        for mname in self.d:
            print("MODEL {} {} records".format(mname, len(self.d[mname])))

    def fulldump(self):
        print(json.dumps(self.d,indent=4, separators=(',', ': '), sort_keys=True))

    def get_dict(self):
        return self.d


class Sync:

    def __init__(self):
        self.models = dict()
    
        self.reclist = RecList()
        self.model_map_backup = dict()
        self.model_map_restore = dict()
        """ one to one models """
        
        self.follow_order = dict()
        """ model hierarchy """
        
        self.extrafields = dict()
        """ do not delete these fields (restore) """

        self.nofollow = dict()
        """ do not try to backup these models from parens """
        
        self.never_follow = list()
        """ do not try to backup these models at all (e.g. logs) """

        self.rid_field = dict()
        """ field instead of 'rid' (e.g. for Group) """
        
        self.rid_trans = dict()
        """ other one-to-one model instead of this mode """        

        self.trans = dict()
        """ model to model translation """
                    
        for appname in ['okerrui','myauth']:
            app_models = apps.get_app_config(appname).get_models()
            for model in app_models:
                self.models[model.__name__] = model

        self.configure()


    def should_reference(self, parent, child):
        """
            if should reference or not.            
            reference is always by rid of object (or 1-1 object, e.g. 1-1 profile)
        """
        if child in self.never_follow:
            return False
        return True

    def should_follow(self, parent, child):
        """ 
            if should follow or not 
            parent, child - textnames 
            
            following is adding records nested in parent record
        """
        if child in self.never_follow:
            """ we never backup this model at all """
            return False
        
        if parent in self.follow_order and child in self.follow_order[parent]:
            """ explicitly configured to backup it """
            return True

        if parent in self.nofollow and child in self.nofollow[parent]:
            """ explicitly configured not to follow """ 
            """ e.g. 'User' should not follow deep back to 'Profile' """ 
            return False

        for pname in self.follow_order:
            if child in self.follow_order[pname]:                
                """ this is known child but for other parent """
                return False
        
        raise SyncException("ERR! Follow check FAIL ({} > {})".format(parent,child))
        return False
                            
            

    def configure(self):
        self.follow_order['User'] = ['Project', 'BonusActivation']
        self.follow_order['Project'] = ['ProjectMember', 'Policy', 'ProjectTextID', 'ProjectInvite']
        self.follow_order['Project'].append('Indicator')
        self.follow_order['ProjectMember'] = ['User']
                        
        self.follow_order['Policy'] = ['PolicySubnet']
        self.follow_order['Indicator'] = ['IArg']
        self.follow_order['Profile'] = ['Membership', 'ProfileArg']

               
        self.nofollow['Profile']=['User']
        self.nofollow['User']=['Profile']

        self.rid_trans['User']='profile' # rid = UserObj.profile.rid
        self.rid_field['Group']='name'   # rid = GroupObj.name
        
        self.trans['User']='Profile'


        self.never_follow=['LogEntry', 'AlertRecord', 'LogRecord', 'UserSocialAuth', 'IChange','IndicatorTag','CheckMethod', 'Indicator']

        self.model_map_restore['User'] = 'Profile'        
        self.model_map_backup['Profile'] = ['User']
              
        self.extrafields['Profile']=['email', 'password']
    
    def set_rid(self,o):
        if o.rid:
            return False
        o.rid = o.__class__.__name__ + ':' + settings.HOSTNAME + ':' +str(o.id)
        return True

    def set_rid_all(self):
        # fix rid everywhere
        rid_models = [
            okerrui.models.Profile, 
            okerrui.models.Project,
            okerrui.models.Policy,
            okerrui.models.Indicator,
            okerrui.models.ProjectMember
            
        ]
        
        for mdl in rid_models:
            for o in mdl.objects.filter(Q(rid__isnull=True) | Q(rid='')):
                if self.set_rid(o):
                    o.save()

    
    def rid2instance(self,model,rid,parents):
        mname = model.__name__

    
        print("rid2instance of {} {}".format(mname, model))
        print("parents:",parents)
        print("model_map:",self.model_map_restore)
        
        if rid:
            print("rid:",rid)
            pass
        else:
            # print "No rid, look in parents"
            # direct check
            pass

            # model_map check                        
            if mname in self.model_map_restore:
                trans_mname = self.model_map_restore[mname]
                if trans_mname in parents:
                    # print "Found {} > {} ({}) in parents".format(mname,trans_mname,parents[trans_mname])
                    rid = parents[trans_mname]
                    trans_m = self.models[trans_mname]
                    # print "trans model:",trans_m
                    trans_mi = trans_m.objects.get(rid = rid)
                    # print "trans instance:",trans_mi
                    # extract destination instance from this
                    for f in trans_mi._meta.get_fields():
                        if f.is_relation and f.one_to_one:
                            # this relation or not?
                            if f.rel.model == model:
                                # print "THIS relation:", f
                                value = getattr(trans_mi,f.name)
                                print("value:",value)
                                return value
                 
        
        print("ERROR IN rid2instance")
        pass
        
    def restore_helper(self, o, data):
    
        skipfields = ['id']        

        rid = data['rid']
        
        print(data)
    
    
        if isinstance(o,ModelBase):
            print("find by rid:", rid)
            try:
                p = o.objects.get(rid=rid)
            except ObjectDoesNotExist:
                print("Create",o)
                o = o()
        
        # now o is always instance 

        print("restore rid", rid)

        for f in o._meta.get_fields():
        
            if f.name in skipfields:
                continue
        
            if not f.is_relation:
                if f.name in data:
                    if isinstance(f,models.fields.DateTimeField) and data[f.name] is not None:
                        setattr(o, f.name, myutils.unixtime2dt(data[f.name]))
                    else:                
                        # no datetime, simple field
                        setattr(o, f.name, data[f.name])
                else:
                    print("missing key {} in data".format(f.name))
                # print "{} = {}".format(f.name,repr(getattr(o,f.name)))
            elif isinstance(f,models.ForeignKey):
                relmodel = f.related_model
                relname = f.related_model.__name__
                # try to get relrid
                # maybe in parents
                rel_instance = self.rid2instance(f.related_model,None,data['_parents'])
                print("FK to {} {} {}".format(repr(relname), relmodel, rel_instance))
                print(data)
                setattr(o, f.name, rel_instance)


        return o



    def get_rid(self,o):
        """
            return rid of instance O
            or return rid of mapped
                    
            self.model_map_restore['User'] = 'Profile'
        """
        oname = o.__class__.__name__
        
        if oname in self.rid_trans:
            transmodel = self.rid_trans[oname]
            trans = getattr(o,transmodel,None)
            # print "get_rid trans {} ({}) to {} ({})".format(o, oname, trans, transmodel)
            return getattr(trans, 'rid', None)

        if oname in self.rid_field:
            return getattr(o,self.rid_field[oname],None)

        
        return getattr(o,'rid',None)

    
    def fill_fk(self,o,parent_instance):
        """
            take instance
            return dict of all FK filled
        """
        oname = o.__class__.__name__
        
        # print "fill_fk for class",oname
        
        backup = dict()
                
        for f in o._meta.get_fields():
            if isinstance(f,models.ForeignKey):
                # print "+ backup FK {}:{}".format(type(o),f)
                relmodel = f.related_model
                relname = f.related_model.__name__
                # try to get relrid
                # maybe in parents
                rel_instance = getattr(o,f.name)

                if rel_instance == parent_instance:
                    # no need to backup this
                    # print "skip, parent"
                    continue


                # should we make reference?                

                if self.should_reference(oname, relname):                    
                    # print "FK from {} to {} {} {}".format(o.__name__, repr(relname), relmodel, rel_instance)
                    ri_rid = self.get_rid(rel_instance)
                    if ri_rid is not None:
                        backup[f.name] = ri_rid
                    else:
                        # print "ERR ri_rid ({} {} : {}) is None!".format(oname, o, f.name)
                        raise SyncException("ERR ri_rid ({} {} field: {} relmodel: {}) is None!".format(oname, o, f.name, relname))


        # print "fill fk:",backup
        return backup


    
    
    def relations(self,o,parent_instance):
        """
            process only ManyToOne relations (reverse FK)
            return dict of nested models
        """
        oname = o.__class__.__name__
        
        # print "relations",oname
        
        nested = dict()
        
        for f in o._meta.get_fields():
            if isinstance(f,models.fields.reverse_related.ManyToOneRel):
                relmodel = f.related_model
                relname = relmodel.__name__
                
                
                if self.should_follow(oname,relname):
                    #print "ok, follow {} > {}".format(oname, relname)
                    target_model = f.related_model
                    # print "target model:",target_model
                    # print "tm name:",target_model.__name__
                    target_fieldname = f.field.name
                    kwargs = dict()
                    kwargs[target_fieldname] = o
                    # print "kwargs:",kwargs
                    nested[target_model.__name__] = list()
                    
                    # use helper or built-in method?
                    backup_method = getattr(target_model,'syncbackup',None)
                    for to in target_model.objects.filter(**kwargs):
                        # print "to:",to                                                
                        if callable(backup_method):
                            to_backup = to.syncbackup(self,tstamp=None,parent=o)
                        else:                                        
                            to_backup = self.backup_helper(to, o)
                        nested[target_model.__name__].append(to_backup)
                    continue
                # no need to warn here, self.follow() makes warnings                
                # print "WARN many to one {} > {}".format(oname,relname)
            elif isinstance(f, models.ForeignKey):
                if getattr(o,f.name,None) == parent_instance:
                    # it's back to parent, no need to backup it
                    continue
        return nested


    def backup_helper(self, o, parent_instance):
        """
            make dict of fields
        """

        def follow_fk(o,classname):
            for f in o._meta.get_fields():
                if f.one_to_one:
                    if f.related_model.__name__ == classname:
                        value = getattr(o,f.name)
                        return value

            print("ERROR follow_fk")


        # print "!! backup_helper", o.__class__.__name__, o

        short = True # True for debug, to skip long data
        skipfields = ['id']
        oname = o.__class__.__name__
                
        backup = dict()
        for f in o._meta.get_fields():
            if f.name in skipfields:
                continue

            if short:
                if isinstance(o,okerrui.models.Project) and f.name == 'jkeys':
                    continue
                
            if not f.is_relation:
                if isinstance(f,models.fields.DateTimeField):
                    backup[f.name] = myutils.dt2unixtime(getattr(o, f.name))
                else:                
                    backup[f.name] = getattr(o, f.name)
                # print "{} = {}".format(f.name,repr(getattr(o,f.name)))

        # FK
        fkfields = self.fill_fk(o,parent_instance)
        # print "fkfields ({}): {}".format(o,fkfields)
        backup.update(fkfields)

        # direct nested
        nested = self.relations(o,parent_instance)                        
        # print "nested:",nested
        backup.update(nested)

        # indirect nested
        if oname in self.model_map_backup:
            for trans_modelname in self.model_map_backup[oname]:
                of = follow_fk(o,trans_modelname)
                nested = self.relations(of,of)                        
                # print "trans nested:",nested
                backup.update(nested)
        

        return backup


    def backup(self,tstamp):
        self.set_rid_all()
    
        started = time.time()
    
        # ignore tstamp for now
        backup = dict()
        backup['Profile']=list()
        Profile = okerrui.models.Profile
        try:
            for p in Profile.objects.filter(mtime__gte = tstamp):
                backup['Profile'].append(p.syncbackup(self,tstamp))
        except SyncException as e:
            print("SyncError:", e)
            return None        
        
        stopped = time.time()
        
        print("backup done ({} seconds)".format(int(stopped - started)))
        return backup

        
    def dump(self, data):
        print(json.dumps(data,indent=4, separators=(",",": ")))


    # sync.unfold        
    def unfold(self, mname, data,  parents = None):
        """
            used in restore.
            unfold nested
        """
        skipfields=[u'id']
        
        if othermodels is None:
            othermodels = dict()
        
        if parents is None:
            parents = list()
            
        model = self.models[mname]

        # export simple variables
        for mi in data:
            # print model, mi['rid']
            out = dict()
            deep_parents = dict(parents)
            deep_parents[mname] = str(mi['rid'])
                            
            for f in model._meta.get_fields():                            
                keyname = unicode(f.name)
                #print("FIELD {}:{}".format(mname,f.name))
            
                if not f.is_relation:
                    
                    if keyname in skipfields:
                        continue
                    
                    if keyname in mi:
                        #print("ADD FIELD {}:{}".format(mname,f.name))                        
                        out[f.name] = mi[keyname]                    
                            
                    else:
                        print("missing key {} in mi".format(keyname))
                else:
                    # relation

                    deepmname = f.related_model.__name__
                    #print "deepmname:",deepmname
                    if unicode(deepmname) in mi:
                        #print "GO DEEP {} > {}".format(mname,deepmname)
                        self.unfold(deepmname, mi[unicode(deepmname)],
                            parents = deep_parents)
                    else:
                        
                        # check if FK
                        #print "NO GO DEEP {} > {}".format(mname,deepmname)
                                                
                        pass

            if mname in self.extrafields:
                for fname in self.extrafields[mname]:
                    keyname = unicode(fname)
                    out[fname] = mi[keyname] 
                        
            out['_parents'] = parents
            self.reclist.append(mname,out)
            
            # unfold forced nested models
            print("mname:", repr(mname))
            print("othermodels:",repr(othermodels))
            if mname in self.follow_order:
                for nmodel in othermodels[mname]:
                    self.unfold(nmodel, mi[unicode(nmodel)], 
                        parents = deep_parents)                                        
        
    def restore_model(self, mname, data):
        print("restore_model {} ({} records)".format(mname, len(data)))
        model = self.models[mname]
        print(model)
        srm = getattr(model,'syncrestore',None)
        if callable(srm):
            print("has syncrestore")
            for mi in data:
                print(data)
                srm(mi,self)
        else:
            print("has NO syncrestore", srm)
            for mi in data:
                # generic restore
                self.restore_helper(model, mi)
        
        
        
    def smart_restore(self, data):
        """
            call restore_model for each model in proper order
            do post-check after this            
        """
        
        processed = list()
        work = True
                
        while work:
            work = False    
            for mname in data:
                if mname in processed:
                    # already restore this model
                    continue
                    
                # print "consider smartrestore",mname                    
                if len(data[mname]):
                    can_restore = True
                    mi = data[mname][0]
                    for pname in mi['_parents']:                    
                        # print "{} has parent {} (restored: {})".format(mname,pname, pname in processed)
                        if not pname in processed:
                            # print "Cannot restore  {} because of parent {}".format(mname, pname)
                            can_restore = False
                    if can_restore:
                        print("RESTORE {}".format(mname))
                        self.restore_model(mname, data[mname])
                        processed.append(mname)
                        work = True
                        break                 
                else:
                    print("skip {} because empty".format(mname))
    
        # post check
        for mname in data:
            if mname in processed:
                pass
            else:
                print("NOT RESTORED model {} ({} records)".format(mname,len(data[mname])))
    
    
    def restore(self,data):
                
        for mname in data:
            print("RESTORE WILL UNFOLD",mname)
            self.unfold(mname, data[mname])
        
        self.reclist.dump()
        # self.reclist.fulldump()
        
        data = self.reclist.get_dict()        
        self.smart_restore(data)
        
        return
        print("+ Restore profiles...")
        for p in data['Profile']:
            print("restore profile {}".format(p['email']))
            okerrui.models.Profile.syncrestore(p)
                       
