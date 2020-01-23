#
# Object manager
#
#
#
#

from django.core.exceptions import ObjectDoesNotExist
from django.db import models
from django.db.utils import IntegrityError

#import dateutil
import timestring
import myutils
import string


class ArgError(Exception):
    pass

class OMan(object):

    def __init__(self,cls,keyfield):
        self.cls = cls
        self.keyfield = keyfield

        # fields
        self.fields = []
        self.fkeys = {}
        self.seconds_columns = []
        self._reqargs = {}

        for f in cls._meta.get_fields():
            if f.is_relation:            
                if isinstance(f,models.ForeignKey):
                    self.fkeys[f.name] = f.related_model    
                
            else:
                self.fields.append(f.name)
        
                
        # other tables and their key field
        self.tables=dict()

    
    def reqarg(self, argname, otherarg):
        if isinstance(otherarg,list):
            for oa in otherarg:
                self.addreqarg(argname,oa)
            return
        
        # otherarg is not list here, must be string
        
        # make sure we have list for argname 
        if not argname in self._reqargs:
            self._reqargs[argname] = []
            
        if not otherarg in self._reqargs[argname]:
            self._reqargs[argname].append(otherarg)
        

    #
    # Table lookup field (unique)
    #
    # table name, unique field name
    # 
    # e.g. author, name
    #
    #    
    def table_key_field(self, tname, ufield):
        self.tables[tname]=ufield
        
    def seconds_column(self,column):
        self.seconds_columns.append(column)
    
    def args(self,parser):
        parser.add_argument('--get', default=False, metavar='ID', help='Work with one object. Provide id or value of field {}'.format(self.keyfield))
        parser.add_argument('--all', default=False, action='store_true', help='Work with all objects')
        parser.add_argument('--really', default=False, action='store_true', help='Really do. (required for dangerous operations)')
        parser.add_argument('--show', default=False, action='store_true', help='Show using model unicode() or strdump()')
        parser.add_argument('--dump', default=False, action='store_true', help='Raw dump of fields')
        parser.add_argument('--format', default=False, help='Format dump of fields, e.g. id: $id name: $name')
    
        parser.add_argument('--create', default=None, metavar=self.keyfield.upper(), help='Create object')
        parser.add_argument('--delete', default=False, action='store_true', help='Delete object')
        parser.add_argument('--setvar', default=[], action='append', nargs=2, metavar=("field","VALUE"), help='Set args for object')
        parser.add_argument('--unset', default=[], action='append', metavar="field", help='Unset args for object')
        parser.add_argument('--nosave', default=False, action='store_true', help='Do not save object')


        for fname in self.fields:
            parser.add_argument('--'+fname, default=None, help='set field {} (or default)'.format(fname))


        for fname in self.fkeys:
            parser.add_argument('--'+fname, default=None, help='set foreign key to {}'.format(self.fkeys[fname]))



    def get(self,get):
        """
        get object by id if int(get) or by keyfield
        """
        d = {}

        try:
            d['id']=int(get)
        except ValueError:
            # id was string
            d[self.keyfield] = get
        try:
            o = self.cls.objects.get(**d)
        except ObjectDoesNotExist:
            print "No such object! {}".format(repr(d))
            return None

        return o
            

    
        
    def show(self,o):
        if hasattr(o,'strdump'):
            print o.strdump()
        else:
            print str(o)
    
    
    def format(self,o,fmt):
        variables = o.__dict__
        tpl = string.Template(fmt)
        print tpl.safe_substitute(variables)
    
    
    def dump(self,o):
        print "=== {}:{}".format(o._meta.model_name,o.pk)
        for f in o._meta.get_fields():
            if f.is_relation:
                if isinstance(f,models.ForeignKey):
                    print "{} (FK): {}".format(f.name,repr(getattr(o,f.name)))
                
            else:
                print "{} = {}".format(f.name,repr(getattr(o,f.name)))
            # type(f), dir(f)   
        print
    
    def unset(self,o,name):
        print "unset {}".format(name)
        
        f = o._meta.get_field(name)
        print "f: {} ({})".format(f,type(f))
        print "default: {}".format(f.default)
        setattr(o,name,f.default)
        pass
    
    def setvar(self,o,name,value):    
    
        if name in self.fkeys:
            # foreign key
            fcls = self.fkeys[name]
            # fkname = self.tables[fcls.name]
            fk_fname = self.tables[fcls]
            getargs = dict()
            getargs[fk_fname] = value
                        
            fo = fcls.objects.get(**getargs)
            setattr(o,name,fo)
            
            # print "SETVAR {} FK to {} field {}".format(name, fcls, fkname)
        else:
            # simple case
            fc = o._meta.get_field(name)
            if isinstance(fc, models.BooleanField):
                if value.lower() == 'true':
                    setattr(o,name,True)
                elif value.lower() == 'false':
                    setattr(o,name,False)
                else:
                    print "ERROR! Boolean value for {} must be either True or False"
            elif isinstance(fc, models.IntegerField):
                if name in self.seconds_columns:
                    value = myutils.str2dt(value).total_seconds()
                setattr(o,name,int(value))
            elif isinstance(fc, models.DateTimeField):
                d = timestring.Date(value, tz='UTC').date
                setattr(o,name,d)
            else:            
                setattr(o,name,value)
    
    def cmd(self, options, o):
        # print "run CMD for {}".format(o)
        
        changed = False
        worked = False
        
        if options['create']:
            self.setvar(o,self.keyfield, options['create'])
            changed = True
            worked = False                
        
        if options['unset']:
            print "unset: ",options['unset']
            for u in options['unset']:
                self.unset(o,u)
                changed = True
                worked = False
        
        if options['setvar']:
            for sv in options['setvar']:
                self.setvar(o,sv[0], sv[1])
                changed = True
                worked = False

        # process --fieldname options
        for f in self.fields:
            if options[f] is not None:
                self.setvar(o,f,options[f])
                changed = True
                worked = True

        for f in self.fkeys:
            if options[f] is not None:
                self.setvar(o,f,options[f])
                changed = True
                worked = True

        
        if options['show']:
            self.show(o)
            worked = True

        if options['format']:
            self.format(o,options['format'])
            worked = True

            
        if options['delete']:
            o.delete()            
            worked = True
        
        
        
        if options['dump'] or not worked:
            # default - show
            self.dump(o)
        return changed

    # save? 
    def saveq(self,options,o):
        if not options['nosave']:
            try:
                o.save()
            except IntegrityError as e:
                print "ERROR: ",str(e)
                


    def argcheck(self,options):        
        """Check options against known _reqargs. Raise ArgError if something is wrong."""
        if not (options['get'] or options ['all'] or options['create']):
            raise ArgError("require either one --get or --all or --create")
                
        for arg in self._reqargs:
            if options[arg]:
                for ra in self._reqargs[arg]:
                    if not options[ra]:
                        raise ArgError('Argument \'{}\' requires arg(s): {}'.format(arg, self._reqargs[arg]))



    def handle(self,options):
        # print "ARGS:",args
        # print "OPTIONS:",options
    
        self.argcheck(options)
            
        if options['all']:
            for o in self.cls.objects.all():
                self.cmd(options,o)
        
        elif options['get']:
            o = self.get(options['get'])
            if o:
                if self.cmd(options,o): # save if needed
                    self.saveq(options,o)
                
        
        elif options['create']:
            o = self.cls()
            self.cmd(options,o)
            self.saveq(options,o)
                
            self.dump(o)            
        else:
            print "SOMETHING STRANGE"
            
            
            
            
            
            
