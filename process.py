#!/usr/bin/env python

#from myutils import *

import os
import sys
import re
import socket
import select
import requests
import time
import hashlib
import argparse
import configargparse
import json
import logging
import logging.handlers
import pwd
import grp
import signal
import fcntl

import getpass
import resource
import gc
# import objgraph

import evalidate
import cron
from myutils import shorttime, lockpidfile,send_email, md_escape
import myutils

#from subprocess import Popen, PIPE
from datetime import datetime, timedelta
import calendar

import telegram
import telegram.ext
from telegram.error import TelegramError

import redis


import django
from django.urls import reverse
from django.utils import timezone
from django.template.loader import get_template
from django.conf import settings
from django.db.models import Count, F
from django.contrib.auth import get_user_model
from django.db import reset_queries
from django.db.models import Max

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "okerr.settings")
django.setup()

from okerrui.models import Indicator, Profile, Policy, LogRecord, CheckMethod, AlertRecord, SystemVariable, Project
from okerrui.impex import myci

from daemon import Daemon

# import okerrclient
import okerrupdate


#log=myutils.openlog()

alertid = 0

class MyDaemon(Daemon):
    def run(self):
        maincode()


def mysignal(signal, frame):
    global stop
    log.debug("stop")
    log.info('{} caught, will quit soon'.format(signal))
    stop=True


def myname():
    try:
        name = os.environ['HOSTNAME']
    except KeyError:
        name = socket.gethostname()
    return name.split('.')[0]


#
# process, unlock and save one indicator
# 

def updatei(i1):
    cm = i1.cm
    now=timezone.now()

    backlog=myutils.chopms(now-i1.scheduled)
    SystemVariable.assign('process-backlog',str(int(backlog.total_seconds())))
    log.info("Processing #{iid} {indicator} cm:{cm} backlog: {backlog}".\
        format(iid=i1.id, indicator=i1,cm=cm,backlog=backlog))                
    log.info("scheduled: {}".format(myutils.chopms(i1.scheduled)))
    i1.action()
    log.info("result: #{iid} {indicator}".format(iid=i1.id, indicator=i1))        
    log.info("scheduled: {}".format(myutils.chopms(i1.scheduled)))    
    return i1
    
    
def updateindicators():
    pid = os.getpid()
    ii = Indicator.objects.filter(lockpid=pid)
    c=0
    for i1 in ii:
        i1 = updatei(i1)
        i1.usave()
        c+=1
    return c


def send_tg_alerts():
    if settings.TGBOT_TOKEN is None:
        return

    bot = telegram.Bot(settings.TGBOT_TOKEN)

    for ar in AlertRecord.objects.filter(proto='telegram', release_time__lte=timezone.now()):
        textid = ar.indicator.project.get_textid()
        iname = ar.indicator.name
        profile = ar.user.profile
        if not profile.telegram_chat_id:
            log.debug('no chat_id for {}'.format(ar.user.username))
            ar.delete()
            continue
        
        
        mdtext = u'[{name}@{textid}]({url}): {text}'.format(
            name = iname,
            textid = textid,
            url = settings.SITEURL + reverse('okerr:ilocator', 
                kwargs = {
                    'pid': textid, 
                    'iid': iname 
                    }),
            text = md_escape(ar.message)
        )

        texttext = u'{name}@{textid}: {text}'.format(
            name = iname,
            textid = textid,
            text = ar.message
        )

        try:
            bot.send_message(
                chat_id=profile.telegram_chat_id, 
                parse_mode = telegram.ParseMode.MARKDOWN,
                text=mdtext)
        except TelegramError as e:
            log.info('Exception: {} msg: {}'.format(e, mdtext))
                       
        log.info(u'sent tg alert to @{} ({}): {}'.format(profile.telegram_name, ar.user.username, texttext))
        ar.delete() 


def send_mail_alerts():

    global alertid

    from_email = settings.FROM
    subject = "okerr alert"
    # print "sendalerts..."
    User = get_user_model()
    
    plaintext = get_template('alert-email.txt')
    htmly     = get_template('alert-email.html')

    # logage_threshold = timedelta(minutes=1)
    logage_threshold = timedelta(seconds=10)    
    now = timezone.now()

    for arec in AlertRecord.objects.filter(proto='mail', release_time__lte=now).\
            values('user').annotate(maxcre=Max('created')):
        age = timezone.now()-arec['maxcre']
        if(age > logage_threshold):
            # send alerts for this user
            user = User.objects.get(pk=arec['user'])        
            p = user.profile
            to = user.email

            siteurl = settings.SITEURL.strip('/')
            count = p.mail_alerts().count()
            log.info(f"Send alert #{alertid} ({count} alerts) to {user.email}")

            d = { 'siteurl': siteurl,'user': user, 'profile':p , 
                'alertid': alertid,
                'hostname': settings.HOSTNAME,
                  'MYMAIL_FOOTER': settings.MYMAIL_FOOTER }

            alertid += 1
            text_content = plaintext.render(d)
            html_content = htmly.render(d)        
            # now delete all alerts for this user
            AlertRecord.objects.filter(user=user, proto='mail').delete()        
            
            #log.info('send alerts to {}'.format(to))
            send_email(to, subject=subject, html=html_content, what='alert')
        else:
            pass
            # log.info('delay alerts for {} ({})'.format(arec['user'], age))
                           
            
        
def send_summaries():
   
    from_email = settings.FROM
    plaintext = get_template('summary-allprojects-email.txt')
    htmly     = get_template('summary-allprojects-email.html')
    subject = 'okerr summary'

    ci = myci()

    #timefrom=timezone.now() - timedelta(seconds=30)   
    #print "timefrom: ",timefrom
    # sql = "sendsummary AND nextsummary<utc_timestamp()"
    for p in Profile.objects.filter(ci = ci, sendsummary=True, nextsummary__lt = timezone.now()):            
        log.info("send summary to {}".format(p.user.email))
        to = p.user.email        
        t = timezone.now()
        
        d = { 
            'profile': p, 
            'remark': 'periodic summary ({} UTC)'.format(t.strftime('%d/%m/%y %H:%M')), 
            'siteurl': settings.SITEURL, 
            'hostname': settings.HOSTNAME,
            'MYMAIL_FOOTER': settings.MYMAIL_FOOTER
            }

        if '*' in settings.MAIL_RECIPIENTS or to in settings.MAIL_RECIPIENTS:
            # text_content = plaintext.render(d)
            html_content = htmly.render(d)

            log.info("send summary ({}) to {}".format(settings.MYMAIL_METHOD, to))

            
            #msg = EmailMultiAlternatives(subject, text_content, from_email, [to])
            #msg.attach_alternative(html_content, "text/html")
            #msg.send()
        
            send_email(to, subject=subject, html=html_content, what='periodic_summary')


            
        else:
            log.info('skip sending summary to {}, because not in MAIL_RECIPIENTS: {}'.format(to, settings.MAIL_RECIPIENTS))


        p.schedulenext()
        p.save()
    

def unlockold(td=None):    
    #log.info('unlocking....')
    now=timezone.now()
    if not td:
        log.debug('onlock all records')
        uq = Indicator.objects.filter(lockpid__isnull=False)
    else:
        log.debug('unlock old locked records ({} ago)'.format(td))
        uq = Indicator.objects.filter(lockpid__isnull=False, lockat__lt=now-td)
    uc = uq.update(lockpid=None,lockat=None)
    log.debug("unlocked {} records".format(uc))
    
    
def lock(ci):
    now=timezone.now()
    numi = 2
    pid = os.getpid()        
    
    remote = False
    
    ids=Indicator.objects.filter(lockpid__isnull=True, ci=ci, cm__remote=remote, problem=False,disabled=False, dead=False, deleted_at__isnull=True, scheduled__lt=now).values_list('pk', flat=True)[:numi]
    # print "ids:",ids
    
    nlocked = Indicator.objects.filter(pk__in=list(ids), lockpid__isnull=True, ci=ci,  cm__remote=remote, disabled=False, deleted_at__isnull=True, scheduled__lt=now).update(lockpid=pid,lockat=now)
    return nlocked


def unlockmy():
    uq = Indicator.objects.filter(lockpid=os.getpid())
    try:
        uq.update(lockpid=None,lockat=None)
    except django.db.utils.OperationalError:
        # ignore it. will unlock on next run
        pass

def loop(ci, send_mail=True):

    r = myutils.get_redis()
    try:
        r.set('process_lastloop', str(int(time.time())))
    except redis.exceptions.ConnectionError as e:
        log.error('Connection Error: {}'.format(e))
        for path in ['/', '/var/', '/var/run', '/var/run/redis']:
            log.info("{}: {}".format(path, os.listdir(path)))

        log.info("loop access: r:{} w:{}".format(
            os.access('/var/run/redis/redis.sock', os.R_OK),
            os.access('/var/run/redis/redis.sock', os.W_OK),
        ))
        log.info("GID: {}".format(os.getegid()))
        log.info("Groups: {}".format(os.getgroups()))


    # print "last loop:",SystemVariable.get('lastloopunixtime')
  
    now = calendar.timegm(datetime.utcnow().utctimetuple())


    SystemVariable.assign('lastloopunixtime',str(now))

    # call fast async routines
    Profile.run_async()

    # unlockold(timedelta(minutes=1)) - not needed, done via indicator.cron
    n = lock(ci)
    log.debug("locked {} records".format(n))
    if n == 0:
        SystemVariable.assign('process-backlog',str(0))
    
    u = updateindicators()
    log.debug("updated {} indicators".format(u))
    unlockmy()
    #print "{} endloop\n".format(shortdate())

    if send_mail:
        send_mail_alerts()
        send_tg_alerts()
        send_summaries()
    return u

def maincode(ci, send_mail=True, lifetime=None, keepalive=True):
    global stop
    stop = False

    print("lifetime:", lifetime)

    signal.signal(signal.SIGTERM,mysignal)
    signal.signal(signal.SIGINT,mysignal)
    log.info('okerr processor pid: {} ci: {} started as user {}, procsleep: {} seconds'.format(
        os.getpid(), ci, pwd.getpwuid(os.getuid())[0], settings.PROCSLEEP))
    iteration = 0
    
    lastmemtime = 0

    started = time.time()    

    last_iupdated = time.time()

    totalu = 0

    if keepalive:
        log.info('Keepalive indicators...')
        c = 0
        totali = Indicator.objects.filter(ci = ci, disabled = False).count()
        for i in Indicator.objects.filter(ci = ci, disabled = False):
            # log.debug('keep {}'.format(i))
            i.reanimate()
            i.save()
            c += 1
            if not c % 100:
                log.info('.. rescheduled {}/{} indicators'.format(c, totali))

        ka_time = time.time() - started;
        log.info('rescheduled {} indicators in {:.2f}s ({:.2f} i/s)'.format(c, ka_time, float(c)/ka_time))

    while not stop:
        if time.time()>(lastmemtime + 600):
            log.info('okerr-process {} uptime: {} Memory usage: {} (kb)'.\
                format(os.getpid(),
                int(time.time() - started),
                resource.getrusage(resource.RUSAGE_SELF).ru_maxrss))
            lastmemtime=time.time()
 
        u = loop(ci, send_mail)
        totalu += u
        
        if time.time() > last_iupdated + 300:
            log.debug('update {} (totalu: {})'.format(myindicator.name, totalu))
            try:
                myindicator.update(totalu, '{} indicators in {:.2f}s'.format(totalu, time.time() - last_iupdated ))
            except okerrupdate.OkerrExc as e:
                log.error('myindicator {} update error: {}'.format(myindicator.name, e))
            totalu = 0
            last_iupdated = time.time()
            
        if u == 0:
            time.sleep(settings.PROCSLEEP)                    
        else:
            # no sleep, we did something, maybe there is other work
            pass
        cron.cron(log)
        iteration+=1
        reset_queries()
        gc.collect()
        
        if lifetime:
            if time.time() > started + lifetime:
                log.warning('Lifetime {} sec passed. Suicide.'.format(lifetime))
                stop = True

    log.info("stop: {}, quitting".format(stop))


def main():

    cflist = ['/etc/okerr/process.conf']

    parser = configargparse.ArgumentParser(description='okerr indicator local processor.', default_config_files = cflist)

    # parser = argparse.ArgumentParser(description='okerr indicator processor.')
    parser.add_argument('--single', dest='single', action='store_true', default=False, help='single run')
    parser.add_argument('--unlock', dest='unlock', action='store_true', default=False,
                        help='unlock all locked indicators')
    
    parser.add_argument('--lockfile', dest='lockfile', default='/var/run/lock/okerr-process.pid')

    parser.add_argument('--ci', type=int, default=None, help='force ci')
        
#    parser.add_argument('--cc',dest='clientconf', default='/etc/okerrclient.conf', help='okerrClient Conf file name')

    parser.add_argument('--nomail', default=False, action='store_true',
                        help='do not send any mail')

    parser.add_argument('--check', dest='check',action='store_true',
                        default=False, help='check lockfile')
    parser.add_argument('--kill', dest='kill', action='store_true',
                        default=False, help='kill by lockfile')
    parser.add_argument('--user', default='okerr')
    parser.add_argument('--id', dest='id', help='run this indicator (iname@textid)', default=None)
    parser.add_argument('-d', dest='daemon', action='store_true', default=False,
                        help='daemon mode')

    g = parser.add_argument_group('Debugging')
    g.add_argument('--nokeepalive', action='store_true', default=False,
                   help='Do not update keepalive indicators (for debug)')
    g.add_argument('--stderr', action='store_true', default=False,
                   help='log to stderr')
    g.add_argument('--lifetime', metavar='SECONDS', default=None, type=int, help='suicide after this time')
    g.add_argument('-q', dest='quiet', action='store_true', default=False,
                        help='quiet mode')
    g.add_argument('-v', dest='verbose', action='store_true', default=False,
                        help='verbose mode')

    args = parser.parse_args()


#    oc.read_config(args.clientconf)

    if args.nomail:
        send_mail = False
    else:
        send_mail = True
    

    if args.verbose:
        log.setLevel(logging.DEBUG)
        log.debug('Verbose mode')
        if args.stderr:
            err = logging.StreamHandler(sys.stderr)
            log.addHandler(err)
        else:
            print("No logging to STDERR, use --stderr")
            log.info("no logging to stderr, use --stderr")

    # drop privileges
    pwnam = pwd.getpwnam(args.user)
    req_uid = pwnam.pw_uid
    req_gid = pwnam.pw_gid
    
    req_groups = [g.gr_gid for g in grp.getgrall() if args.user in g.gr_mem]
    
    if os.getuid() != req_uid:
        # log.info("set gid: {}".format(req_gid))
        os.setgid(req_gid)

        # log.info("set groups: {}".format(req_groups))
        os.setgroups(req_groups)
        log.info("switch to user {} u: {} g: {}".format(
            args.user, req_uid, [ req_gid ] + req_groups))
        os.setuid(req_uid)

    if args.ci is None:
        ci = myci()
    else:
        ci = args.ci

    if args.check:
        if not args.quiet:
            log.debug("check lockfile", args.lockfile)
       
        daemon = MyDaemon(args.lockfile) 
        pid = daemon.lockedpidfile()
        if pid:
            if not args.quiet:
                log.debug("pidfile {} locked by pid {}".format(args.lockfile,pid))
            sys.exit(0)
        else:
            if not args.quiet:
                log.debug("pidfile not locked")
            sys.exit(1)

    if args.kill:
        try:
            with open(args.lockfile, 'r') as pf:
                pid = int(pf.read().strip())
        except ValueError:
            log.debug("bad value in pidfile")
            sys.exit(1)
        except IOError as e:
            log.debug("IOError while read lockfile: {}".format(str(e)))
            sys.exit(0)

        log.debug("kill process {}".format(pid))
        try:
            os.kill(pid,signal.SIGTERM)
        except OSError as e:
            log.debug("IOError while killing: {}".format(str(e)))
        
        if False:
            log.debug("remove pidfile {}".format(args.lockfile))
            try:
                os.unlink(args.lockfile)
            except (OSError, IOError) as e:
                log.debug("OSError while unlunk lockfile: {}".format(str(e)))

        sys.exit(0)


    if args.unlock:
        unlockold()
        return

    if args.id:
        print("process indicator {}".format(args.id))
        now=timezone.now()
        pid = os.getpid()
        
        iname, textid = args.id.split('@')
        
        p = Project.get_by_textid(textid)
        
        i = p.get_indicator(iname)
        if i is None:
            print("no such indicator")
            return
        # (re)lock
        i.lockpid=pid
        i.lockat=now
        
        updatei(i)    
        return
        
    if args.single:

        log.info('process started in single mode')

        loop(ci, send_mail)
    else:

        if os.geteuid()==0:
            msg='you should not run okerr processor as root!'
            log.error(msg)
            sys.stderr.write("{}\n".format(msg))
            return

        if args.daemon:
            daemon = MyDaemon(args.lockfile) 
            if daemon.start():
                log.debug("daemon started")
            else:
                log.debug("already started")
                sys.exit(1)
        else:
            log.debug("foreground mode")
            lockfh=lockpidfile(args.lockfile)
            if lockfh is None:
                if not args.quiet:
                    log.error("pidfile {} already locked".format(args.lockfile))
                sys.exit(1)
                
            maincode(ci, send_mail, args.lifetime, keepalive=(not args.nokeepalive))
            lockfh.close()
            os.unlink(args.lockfile)
 

#oc = okerrclient.OkerrClient()
#myindicator = okerrclient.Indicator('{}:process'.format(myname()), 
#    method='numerical', period=300, oc=oc)

op = okerrupdate.OkerrProject()
myindicator = op.indicator('{}:process'.format(myname()), method='numerical')

stop = False
                
django.setup()
log = logging.getLogger('okerr')                

r = myutils.get_redis()
r.set('process_started', str(int(time.time())))

main()


