#!/usr/bin/env python
from django.core.management.base import BaseCommand, CommandError
from okerrui.models import Profile,Group,Indicator,Project
from okerrui.cluster import myci
from optparse import make_option
from datetime import datetime,timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from myutils import *
#from dateutil.relativedelta import relativedelta
from django.db import connection
import time

class Command(BaseCommand):
    help = 'Manage indicators'

    def add_arguments(self,parser):
        ispec = parser.add_argument_group('Indicator specification')
        ispec.add_argument('--user', default=None, help='user')
        ispec.add_argument('--textid', default=None, help='project TextID')
        ispec.add_argument('--id', default=None, help='indicator ID')
        ispec.add_argument('--sch', action='store_true', default=False, help='Only indicators scheduled to run now')

        cmd = parser.add_argument_group('Commands')
        cmd.add_argument('--asap', action='store_true', default=False, help='Schedule indicator to be tested ASAP (active only)')
        cmd.add_argument('--keepasap', action='store_true', default=False, help='Keep active indicators in project in ASAP')
        cmd.add_argument('--create', action='store_true', default=False, help='create indicator --id (bypass limitations)')
        cmd.add_argument('--delete', action='store_true', default=False, help='delete selected indicators (first, test with --brief!)')
        cmd.add_argument('--enable', action='store_true', default=False, help='enable indicator, (remove disable flag)')
        cmd.add_argument('--disable', action='store_true', default=False, help='set disable flag')
        cmd.add_argument('--wipe', action='store_true', default=False, help='really delete')        
        cmd.add_argument('--touch', action='store_true', default=False, help='touch')        
        cmd.add_argument('--unlock', action='store_true', default=False, help='unlock indicator')
        cmd.add_argument('--setarg', nargs=2, metavar=('NAME','VALUE'), default=False, help='set argument <name> <value>')
        cmd.add_argument('--alert', default=None, help='send alert')
        cmd.add_argument('--OK','--ok', default=None, action='store_true', help='set OK')
        cmd.add_argument('--ERR','--err', default=None, action='store_true', help='set OK')
        cmd.add_argument('--list', default=None, nargs='?', const=True, help='List indicators. Filter by substring. Can be used with --textid')


        opts = parser.add_argument_group('Options')
        opts.add_argument('--brief', action='store_true', default=False, help='dump only brief info for indicator, instead of full dump')
        opts.add_argument('--briefid', action='store_true', default=False, help='show only id of indicator')
        opts.add_argument('--really', action='store_true', default=False, help='really. for --wipe')        
        opts.add_argument('--sleep', default=1, type=float, help='sleep time (for keepasap)')
        opts.add_argument('--ichange', action='store_true', default=False, help='show ichange records')
        opts.add_argument('-q', dest='quiet', action='store_true', default=False, help='quiet mode, do not print extra info')
        opts.add_argument('--sql', default=False, action='store_true', help='show SQL commands')
        

    def getp(self, options):
        if options['textid']:
            return Project.get_by_textid(options['textid'])
        


    def listindicators(self, name, project=None):
        print("All indicators with name: {}".format(name))        
        for i in Indicator.objects.filter(name=name, deleted_at__isnull=True):
            if project and i.project != project:
                continue
            tidlist=list()
            for tid in i.project.projecttextid_set.all():
                tidlist.append(tid.textid)
            print("{} {} ({}): {} {}".format(i.id, i.project.name, i.project.owner,' '.join(tidlist), "DELETED: {}".format(i.deleted_at) if i.deleted_at else ""  ))
        
        
    def geti(self, options):
        iid = options['id']

        qdlist = list()

        if not iid:
            # no warning sometimes
            if options['textid'] or options['keepasap'] or options['list']:                
                return                
            
            print("must have indicator id (--id)")
            return
        
        # if project is set
        if options['textid']:
            p = Project.get_by_textid(options['textid'])
            if p:
                try:
                    i = p.geti(iid)
                    return i
                except ObjectDoesNotExist:
                    return None
                except Indicator.MultipleObjectsReturned:
                    self.listindicators(iid, p)
                    return None


        try:
            iid = int(iid)
            qdlist.append(dict(pk=iid, deleted_at__isnull=True))
        except ValueError:
            # this is name
            pass

        qdlist.append(dict(rid=iid, deleted_at__isnull=True))
        qdlist.append(dict(name=iid, deleted_at__isnull=True))

        # print "qd:", qd


        for qd in qdlist:
            # print "QD:",qd
            c = Indicator.objects.filter(**qd).count()
            
            if c==1:
                return Indicator.objects.get(**qd)
            if c>0:
                self.listindicators(iid)

        return None


    def handle(self, *args, **options):
        #print "options:",options
        now = timezone.now()
        User = get_user_model()


        # guess textid
        if 'id' in options and options['id'] is not None and '@' in options['id']:
            options['id'], options['textid'] = options['id'].split('@')


        i = self.geti(options)
        p = self.getp(options)


        if options['setarg']:                            
            i.setarg(options['setarg'][0],options['setarg'][1])
            i.fulldump()
            return       
        
        if options['ichange']:
            for ic in i.ichange_set.order_by('created'):
                print(ic)
            return
        
        if options['create']:
            if not p:
                print("Need project (--textid)")
                return                
            if i:
                print("ERR: already have")
                return

            i = Indicator.create(p,options['id'],limits=False)
            print(i)
            return
        
        if options['delete']:
            print("delete",i)                        
            #i.set_delete()
            #i.touch()
            #i.save()
            i.delete()
        
        if options['touch']:
            i.touch()
            i.save()
            return
            
        if options['list']:
            
            
            qs = Indicator.objects.all()
            
            if p:
                qs = qs.filter(project = p)
                                                
            if isinstance(options['list'], str):
                qs = qs.filter(name__contains = options['list'])                
            
            for i in qs:
                print(i)
            
            return
        
        if options['OK']:
            print("set ok for", i)
            i.status = 'OK'
            i.save()
            return
        
        if options['ERR']:
            print("set err for", i)
            i.status = 'ERR'
            i.save()
            return
        
        if options['alert']:
            if i is None:
                print("must have valid indicator")
                return
            i.alert(options['alert'])
            return
        
        if options['wipe']:
            if options['really']:
                i.delete()
            else:
                print("You are not really")
            return
        
        
        # unified handling of --id commands
        if options['id']:
            if i is None:
                print("No such indicator")
                return
            
            if options['enable']:
                i.disabled=False
                i.save()
            if options['disable']:
                i.disabled=True
                i.save()
            if options['unlock']:
                i.unlock()
                i.save()                
            if options['asap']:
                i.retest()
                i.save()
            if options['setarg']:            
                i.setarg(options['setarg'][0],options['setarg'][1])
            # show results if not quiet mode
            if not options['quiet']:
                i.fulldump()
            return       
            



        if options['textid']:
            if not options['quiet']:
                print('get project for textid: ',options['textid'])
            
            prj = Project.get_by_textid(options['textid'])
            if prj:
                
                if options['keepasap']:
                    period = 60
                    n=0
                    started = time.time()
                    
                    while True:
                        for i in prj.indicator_set.all():
                            if i.cm.active():
                                if i.scheduled > timezone.now():
                                    if options['verbosity']>=1:
                                        print("retest", i)
                                    i.retest()
                                    i.unlock()
                                    i.save()
                                    n += 1
                                else:
                                    if options['verbosity']>=2:
                                        print("skip retest", i)
                                    
                        time.sleep(options['sleep'])
                        
                        if time.time() > started + period:
                            print("retested {} indicators in {}s".format(n, period))
                            n = 0
                            started = time.time()
                        
                else:

                    if not options['quiet']:
                        print("Project: {}".format(prj))
                        # print "tags: ",prj.tags()
                    
                    for i in prj.indicator_set.all():
                        if options['unlock']:
                            print("unlock", i)
                            i.unlock()
                            i.save()
                        elif options['asap']:
                            if i.cm.active():
                                print("retest", i)
                                i.retest()
                            i.unlock()
                            i.save()
                        else:
                            if options['quiet']:
                                print(i.name)
                            else:
                                i.fulldump("    ")
                                   
                    if options['sql']:
                        cq = connection.queries
                        totalc=0
                        totaltime=0
                        print("SQL:")
                        for q in cq:
                            totalc+=1
                            totaltime+=float(q['time'])
                            print(q['sql'])
                        print("total: {} queries, {} seconds".format(totalc,totaltime))

                        
            else:
                print("cannot find such project with textid {}".format(options['textid']))
            return

        if options['user']:         
            print("show for user: ", options['user'])
            u = User.objects.filter(username=options['user']).first()
                                    
            if u:
                for prj in u.project_set.all():
                    print("project: ",prj) 
                    for i in Indicator.objects.filter(project=prj):                
                        i.fulldump("  ")
            else:
                print("no profile for {}".format(options['user']))
                return
        else:
            # no specific user given
            iid = options['id']
            if not iid:
                for p in Profile.objects.all():
                    u = p.user
                    print("=== User: {}".format(u))
                    
                    for prj in u.project_set.all():
                        print("    project: {}".format(prj))                                                        
                        iq=Indicator.objects.filter(project=prj)
                        if options['sch']:
                            iq=iq.filter(scheduled__lt=now, ci=myci())
                        for i in iq:
                            i.fulldump("  ")
                return
            try:
                i = Indicator.objects.get(pk=options['id'])
            except ObjectDoesNotExist:
                print("No such indicator")
                return
            i.fulldump("  ")
        



