#!/usr/bin/env python

import smtpd
import asyncore
import os
import sys
import re
import logging
import signal
import argparse
import pwd
import resource
import socket

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "okerr.settings")
import django

from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import get_user_model
from django.db import reset_queries

import email

#import okerrclient
from okerrupdate import OkerrProject

from myutils import lockpidfile
from daemon import Daemon

django.setup()
# from okerrui.models import Indicator, Project, Profile, Policy, LogRecord, CheckMethod

# global
log = logging.getLogger('okerr')                
#oc = okerrclient.OkerrClient()
#oc.read_config()
#oc.log = log




def myname():
    try:
        name = os.environ['HOSTNAME']
    except KeyError:
        name = socket.gethostname()
    return name.split('.')[0]

my_op = OkerrProject()
hb = my_op.indicator("{}:smtpserver".format(myname()))

def mysignal(signal, frame):
    global stop
    log.info('{} caught, will quit soon'.format(signal))
    sys.exit(0)

class MyDaemon(Daemon):
    def run(self):
        signal.signal(signal.SIGTERM,mysignal)
        signal.signal(signal.SIGINT,mysignal)
        asyncore.loop()

class CustomSMTPServer(smtpd.SMTPServer):
    
    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        data = data.decode('utf-8')

        log.info('Memory usage: {} (kb)'.\
            format(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss))
 
        m = re.match('Received:.*\[([0-9\.]+)\]', data)
        if m:
            remoteip = m.group(1)
        else:
            remoteip = None

        em = email.message_from_string(data)

        for part in em.walk():
            if part.get_content_type() == 'text/plain' and part.get_content_disposition() in [None, 'inline']:
                payload = part.as_string()
                break

        log.info('{ip}:{port} ({remoteip}) {fromemail} -> {toemail} len:{length}'\
            .format(ip=peer[0], port=peer[1],
                    remoteip=remoteip,fromemail=mailfrom,toemail=rcpttos,length=len(data)))

        #for rcpt in rcpttos:
        # get left part
        textid,rest = rcpttos[0].split("@",1)

        op = OkerrProject(textid)


        #try:
            #project = Project.objects.get(projecttextid__textid=left)
        #    textid = lef
        #except ObjectDoesNotExist:
        #    log.info('not found project {}'.format(left).encode('utf8'))
        #    return

        #log.info('project: {}'.format(project.name).encode('utf8'))
        sets = {}                

        # now parse email to find 
        pattern = \
        '%%%\s*(?P<idname>[0-9a-zA-Z\_\-\.\:]+)\.(?P<field>[0-9a-zA-Z\_\-]+)\s*=\s*(?P<value>[^\r\n]*)'

        for m in re.finditer(pattern,payload):
            idname = m.group('idname')
            fieldname = m.group('field')
            value = m.group('value')

            log.debug("{textid}: {idname} {fieldname} = {value}"\
                .format(textid=textid, idname=idname, fieldname=fieldname, value=value))
            if not idname in sets:
                sets[idname]={}
                
            sets[idname][fieldname]=value

        # update sets
        for s in sets:
            ss = sets[s]
            #method = None
            #oc.set_arg('textid',textid)
            #oc.set_x('smtp','1')
            #oc.set_x('remoteip', remoteip)
            #sequence = list()

            i = op.indicator(s)
            if 'secret' in ss:
                i.secret = ss['secret']
            status = ss['status']
            details = ss.get('details','')

            log.info("Update {}@{} = {} ({})".format(
                s, textid,
                status,
                details
            ))
            # oc.runseq(name=s, sequence = sequence, method = method)
            i.update(status, details)

        update_status = hb.update('OK')
        # log.info('heartbeat update {} {}'.format(hb, "OK" if update_status else "FAILED"))


def main():

    parser = argparse.ArgumentParser(description='okerr smtp server.')
    parser.add_argument('--lockfile',dest='lockfile',
        default='/var/run/lock/okerr-smtpd.pid')

    parser.add_argument('--check',dest='check',action='store_true',
        default=False,help='check lockfile')
    parser.add_argument('-q',dest='quiet',action='store_true',default=False,
        help='quiet mode')
    parser.add_argument('--kill',dest='kill',action='store_true',
        default=False,help='kill by lockfile')
    parser.add_argument('--user',default='okerr')
    parser.add_argument('-a','--address',default='127.0.0.1')
    parser.add_argument('-p','--port',type=int, default=10025)

    parser.add_argument('-d', dest='daemon', action='store_true', default=False,
        help='daemon mode')
    parser.add_argument('-v', dest='verbose', action='store_true', 
        default=False, help='verbose mode')
    parser.add_argument('--stderr', dest='stderr', action='store_true', 
        default=False, help='log to stderr')
   

    args = parser.parse_args()  

    if args.verbose or args.stderr:
        err = logging.StreamHandler(sys.stderr)
        log.addHandler(err)

    if args.verbose:
        log.setLevel(logging.DEBUG)

    my_op.setlog(log)

    # drop privileges
    requid = pwd.getpwnam(args.user).pw_uid

    if os.getuid() != requid:
        os.setuid(requid)

    if args.check:
        if not args.quiet:
            print("check lockfile",args.lockfile)
        daemon = MyDaemon(args.lockfile) 
        pid = daemon.lockedpidfile()
        if pid:
            if not args.quiet:
                print("pidfile {} locked by pid {}".format(args.lockfile,pid))
            sys.exit(0)
        else:
            if not args.quiet:
                print("pidfile not locked")
            sys.exit(1)

    if args.kill:
        try:
            pf = file(args.lockfile,'r')
            pid = int(pf.read().strip())
            pf.close()
        except ValueError:
            print("bad value in pidfile")
            sys.exit(1)
        except IOError as e:
            print(e)
            sys.exit(0)

        print("kill process {}".format(pid))
        try:
            os.kill(pid,signal.SIGTERM)
            # try not to unlink
        except OSError as e:
            if e.errno == 2:
                # thats fine, atexit deleted pidfile
                pass
            else:
                print("OSERROR (errno: {}): {}".format(e.errno,e))
        if os.path.exists(args.lockfile):
            os.unlink(args.lockfile)
        sys.exit(0)


    if os.geteuid()==0:
        msg='you should not run okerr processor as root!'
        log.error(msg)
        sys.stderr.write("{}\n".format(msg))
        return

    print("bind to {}:{}".format(args.address, args.port))
    server = CustomSMTPServer((args.address, args.port), None)
 
    if args.daemon:
        daemon = MyDaemon(args.lockfile) 
        if daemon.start():
            print("daemon started")
        else:
            print("already started")
            sys.exit(1)
    else:
        print("foreground mode")
        log.debug('fg mode')
        lockfh=lockpidfile(args.lockfile)
        if lockfh is None:
            if not args.quiet:
                print("pidfile already locked")
            sys.exit(1)
        asyncore.loop()
        lockfh.close()
        os.unlink(args.lockfile)
 
main()
