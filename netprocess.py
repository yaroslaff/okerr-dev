#!/usr/bin/env python

import argparse
import configargparse
import requests
import json
import logging
import os
import sys
import pwd
import urllib.parse
import time
import smtplib
import shlex
from email.mime.text import MIMEText
import socket
import signal
import resource
import gc
import redis
import crcache

from multiprocessing import Process, Lock, active_children
from multiprocessing import Queue as mpQueue

from setproctitle import setproctitle

import okerrupdate
import counters
from myutils import exc2str


#from pympler.tracker import SummaryTracker
#tracker = SummaryTracker()
dumped = 0

redis_dbi = None

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "okerr.settings")
#django.setup()

# import okerrui.models
from okerrui.remotecheck import check_result
from workerpool import WorkerPool
from okerrui.cluster import RemoteServer

version = "1.0"

#
# Settings
#
user_agent = 'okerr-netprocess/{}'.format(version)
headers = {'User-Agent': user_agent}

#
# init
#
stop = False
stop_set = 0

started = time.time()
last_reported = 0

serial = 0
procname = 'main'



class Command():    
    def __init__(self, command):
        self.command = command


def get_redis():
    if 'REDIS_HOST' in os.environ:
        while True:
            try:
                return redis.Redis(host=os.environ['REDIS_HOST'], port=6379, db=redis_dbi)
            except redis.exceptions.ConnectionError as e:
                log.warning('Redis not ready. Sleep and retry...')
                time.sleep(1)
    else:
        rsocks = [ '/var/run/redis/redis-server.sock', '/var/run/redis/redis.sock' ]
    
        for rs in rsocks:
            if os.path.exists(rs):
                r = redis.Redis(unix_socket_path=rs, decode_responses=True, db=redis_dbi)
                return r

def sighandler(signum, frame):
    global stop, stop_set
    log.info("{} {} caught signal {}".format(os.getpid(), procname, signum))
    stop_set = int(time.time())
    stop = True


def make_argparser():

    cflist = [ '/etc/okerr/netprocess.conf' ]

    if os.getenv('CLUSTER_URL', None):
        def_cluster = [ os.getenv('CLUSTER_URL') ]
    else:
        def_cluster = None


    parser = configargparse.ArgumentParser(description='okerr indicator network processor.', default_config_files = cflist)

    locg = parser.add_argument_group('Location')   
    locg.add_argument('--name', default=os.getenv('NETPROCESS_NAME','noname'))
    locg.add_argument('--location', default=os.getenv('NETPROCESS_LOCATION','nowhere.tld'))
    locg.add_argument('--checkfilter', default='')    


    specg = parser.add_argument_group('Specification')   

    specg.add_argument('-c',dest='conf', is_config_file=True, help='conf file name')
    # specg.add_argument('--cc',dest='clientconf', default='/etc/okerrclient.conf', help='okerrClient Conf file name')
    specg.add_argument('--user',default='okerr', help='Switch to username. Default: okerr')
    specg.add_argument('--cluster', action='append',
                       help='URL prefix, like https://cp.okerr.com/ (any node in cluster which will list cluster)',
                       default=def_cluster)
    specg.add_argument('--url',default=None, help='Base url, e.g. https://alpha.okerr.com/')
    specg.add_argument('--iname', default=None, help='process only this indicator name, can be iname@textid')
    specg.add_argument('--textid', default=None)

    cmdg = parser.add_argument_group('Commands')   
    cmdg.add_argument('--check', default=None, help="Manual run one check: 'httpstatus|status=200|url=http://www.ru/'")


    poolg = parser.add_argument_group('Pool arguments')   
    poolg.add_argument('--pool', default='p', help='Pool method: mp, p')
    poolg.add_argument('--restart_pool', type=int, default=120,help='Restart pool every N seconds')   
    poolg.add_argument('--workers', type=int, default=10)   
    poolg.add_argument('--maxtasksperchild', type=int, default=5)   
    poolg.add_argument('--force_restart_pool', type=int, default=10,help='If not restarted gracefully in restart_pool seconds, force restart in N seconds')   
    poolg.add_argument('--maxlocked', type=int, default=None,help='max locked indicators')   
    poolg.add_argument('--maxsch', type=int, default=10,help='max scheduled indicators')   


    optsg = parser.add_argument_group('Options')   
    optsg.add_argument('--single', dest='single', action='store_true',
                   default=False,
                   help='single run')
    optsg.add_argument('-q', dest='quiet', action='store_true', default=False,
        help='quiet mode')
    optsg.add_argument('-v','--verbose', dest='verbose', action='store_true', default=False,
        help='verbose mode')
    optsg.add_argument('--sleep',type=float,default=1,help='idle sleep')
    optsg.add_argument('--num', type=int, default=5, help='num of indicators to take in one run')
    optsg.add_argument('--dbi', type=int, default=2, help='redis database index (default: 2)')

    simg = parser.add_argument_group('Simulation')   
    simg.add_argument('--numi', type=int, default=None)
    simg.add_argument('--template', default='sslcert:{}@bench')    
    simg.add_argument('--status', default='OK')    
    
    geng = parser.add_argument_group('General')   
    geng.add_argument('--report', default=None, metavar='SECTIONS', const='', nargs='?', help='report sections: all, pids, stage, q, scheduled, submitted, locked, check_process or servername in form of machine:localhost:8000:q')
    geng.add_argument('--slow', action='store_true', default=False, help='slow test')

    
    return parser


def report(sections=''):
    
    def nicenum(num):
        if num is None:
            return '0'
        num = float(num)
        if num == int(num):
            return "{}".format(int(num))
        else:
            return "{:.2f}".format(num)
    
    def vprint(section, sections, line=''):
        if 'all' in sections:
            print(line)
        if isinstance(section,str):
            section = [section]
        
        for sname in section:
            if sname in sections:
                print(line)
    
    
    def getval(r, key):
    
        if isinstance(key, list):
            s = 0
            for subkey in key:
                s += getval(r, subkey)
            return s    
    
        if key.startswith('?re:'):
            keyre = key.split(':', 1)[1]
            s = 0
            for subkey in r.keys(keyre):
                s += getval(r, subkey)
            return s 
    
    
        if key.startswith('-'):
            return -getval(r, key[1:])
    
        keyt = r.type(key)
        if keyt == "string":
            return int(r.get(key))
        elif keyt == "set":
            return r.scard(key)
        elif keyt == "zset":
            return r.zcard(key)
        elif keyt == "none":
            return 0
        else:
            log.error("unknown type {} for {}".format(keyt, key))
                     
       

    redis_conn = get_redis()
    assert(redis_conn)


    now = time.time()
    summary = dict()
    print("Database report:\n--\n")
    
    diag = {
        'counter:fetched': ['scheduled','counter:launched','counter:main:checkfiltered','-counter:sender:rescheduled', 
            '-counter:check:suppressed'],
        'counter:launched': ['check_process','counter:check:checked','counter:check:not_actual'],
        'counter:check:checked': ['counter:check:suppressed','?re:machine:*:q','counter:sender:dequeued','-counter:main:checkfiltered','-counter:sender:reinjected'],
        'counter:sender:dequeued': ['counter:sender:not_actual','counter:sender:submitted', 
            'counter:sender:not_submitted'],
        'counter:sender:submitted': ['counter:sender:sending','counter:sender:updated','counter:sender:reinjected'],
        'counter:sender:updated': ['counter:sender:applied','counter:sender:not_applied']
    }
    
    
    # get pids
    print("PIDs:\n--")
    for pidname in ['sender_pid','fetcher_pid']:
        pid = redis_conn.get(pidname)
        ttl = redis_conn.ttl(pidname)
        vprint('pids', sections, "  {}: {} (ttl: {}s)".format(pidname, pid, ttl))
        summary[pidname] = pid
        summary[pidname+'_ttl'] = ttl
    
    vprint('pids',sections)
    
    
    # get queues
    qlist = ['scheduled','submitted','locked','check_process']
                
    for qname in redis_conn.keys('machine:*'):
        qlist.append(qname)
         
    for setname in qlist:
        set_type = redis_conn.type(setname)
        if set_type == 'none':
            print("{}: {}".format(setname, repr(set_type)))
        elif set_type == 'set':
            print("{} ({}):".format(setname, redis_conn.scard(setname)))
            summary[setname] = redis_conn.scard(setname)
            for item in redis_conn.smembers(setname):
                vprint(['q',setname], sections, u'  {}'.format(item))
        elif set_type == 'zset':
            print("{} ({}):".format(setname, redis_conn.zcard(setname)))
            summary[setname] = redis_conn.zcard(setname)
            for i, score in redis_conn.zrangebyscore(setname,'-inf','+inf', withscores=True):
                if score<time.time():
                    nowline="now"
                else:
                    nowline="({}s)".format(int(score - now))
                vprint(['q',setname], sections, "{} {} {}".format(int(score),i,nowline))
        else:
            print("unknown type: {}".format(repr(set_type)))
        print()


    if 'fids' in sections or 'all' in sections:
        print("Fids:\n--")
        fids = redis_conn.hgetall('fids')
        print(json.dumps(fids, sort_keys=True, indent=4))

    if 'counters' in sections or 'all' in sections:
        print("Counters:\n--")
        for cname in redis_conn.keys('counter:*'):
            val = redis_conn.get(cname)
            print("  {}: {}".format(cname, val))
            summary[cname] = val
        print()

    stage = redis_conn.hgetall('stage')
    if stage:
        summary['stage'] = len(stage)
        print("Stage ({}):".format(len(stage)))
        vprint('stage', sections, "--")
        for k,v in stage.items():
            vprint('stage', sections, "{}: {}".format(k,v))
    else:
        print("no stage")            
    vprint(u'stage', sections)    
    
    print("Summary:\n--")
    
    for k in sorted(summary.keys()):
        print("  {}: {}".format(k, nicenum(summary[k])))
    print()
    
    if 'diag' in sections or 'all' in sections:
        print("Self-diag:\n--")
        for k,v in diag.items():
            left = getval(redis_conn, k)
            right = getval(redis_conn, v)
            
            if left == right:
                print("OK {} ({}) = {} ({})".format(k, left, v, right))
            else:
                print("ERR {} ({}) = {} ({}), difference: {}".format(k, left, v, right, left - right))
        print



def simulate(machine, num, template, status):
    print("Simulate {} indicators {} at machine {} status {}".format(num, template, machine, status))
    for i in xrange(1,num+1):
        fullname = template.format(i)
        iname, textid = fullname.split('@')
        
        cr = check_result(status = status, details='simulation')
        cr.name = iname
        cr.textid = textid
        cr.code = 200
        machine.add_tproc_result(cr)

    send_start = time.time()
    print("{:.2f} send...".format(send_start))
    r = machine.send_tproc_results(
        force=True, 
        options = dict(simulation = 1))
    print("{:.2f} done ({:.2f}s)".format(time.time(), time.time() - send_start))
    print(json.dumps(r, indent=4))

def check1(cr):
    global procname        
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    try:           
        title = u'netprocess: {}@{}'.format(cr.name, cr.textid)
    except UnicodeDecodeError as e:
        print("ZZZZZ EXCEPTION", str(e))
        print("name:", type(cr.name), cr.name)
        print("textid:", type(cr.textid), cr.textid)
        return
    
    setproctitle(title)
    procname = 'check'        

    cr_cache = crcache.CRCache(get_redis())

    cr_cache.r.sadd('check_process',os.getpid())

    #log.info('check1 started {} {}'.format(os.getpid(), cr.fullname))

    cr_cache.r.incr('counter:check1:started')                            
        
    run_tproc(cr)            

    cr_cache.r.incr('counter:check:aftercheck')                            

    if not cr_cache.still_actual(cr):
        cr_cache.r.incr('counter:check:not_actual')
        cr_cache.r.srem('check_process',os.getpid())
        return

    cr_cache.r.incr('counter:check:checked')                            
    
    if cr.suppress() and not stop:                    
        cr.reborn()
        cr_cache.store(cr, recname = make_ihashname(cr.fullname), schedule=True, target='scheduled') 
        cr_cache.r.incr('counter:check:suppressed')
        log.debug('suppress and reschedule {} = {}'.format(cr.fullname, cr.status))
    else:                    
        cr_cache.stage(cr.fullname, "checked")
        cr_cache.store(cr, make_ihashname(cr.fullname), 
            target='machine:' + cr.rs_name + ':q')
        if not cr_cache.still_actual(cr):
            cr_cache.r.incr('counter:check:not_actual:POST')

    cr_cache.r.incr('counter:check:stopped')                            
    cr_cache.r.srem('check_process',os.getpid())


def run_tproc(cr):
    try:
        cr.check()
    except Exception as e:
        log.error(u'!!!!!!!: {}'.format(exc2str(e)))
        cr.status = 'ERR'
        cr.details = exc2str(e)
    return cr
    

def urlsrv(name, url):
    ud = dict()
    ud['name'] = name
    ud['url'] = url
    ud['next'] = 0
    return ud


def error(msg):
    hostname = socket.gethostname().split('.')[0]
    rcpt_list = settings.LOGMAIL
    me = 'noreply@okerr.com'
    
    print("ERROR:",msg)
    s = smtplib.SMTP('localhost')
    
    for rcpt in rcpt_list:
        message = MIMEText(msg)
        message['Subject'] = 'netprocess alert from '+hostname
        message['From'] = me
        message['To'] = rcpt
        s.sendmail(me, rcpt, message.as_string())
    s.quit()

def myname():
    try:
        name = os.environ['HOSTNAME']
    except KeyError:
        name = socket.gethostname()
    return name.split('.')[0]
        
def check_process(rs):
    
    if time.time() > rs.last_check_process + 1200:
        try:
            llut = int(rs.getsysvar('lastloopunixtime'))
            age = int(time.time())-llut
            if age>300:                
                error("Too old lastloopunixtime on {} {} age: {}".format(rs.name, llut, age ))
                
        except Exception as e:
            error("{}: check_process({}): {}".format(
                socket.gethostname(),
                rs.name,
                str(e)))    
        rs.last_check_process = int(time.time())


def make_ihashname(fullname):
    global serial
    serial += 1
    ### fullname = forceunicode(fullname)
    fullname = str(fullname)
    
    return u'{}:{}:{}:{}'.format(procname, os.getpid(), serial, fullname)

def process_loop_fetcher(machines, sleep=1, maxlocked = None, maxsch = 10, lifetime = 600):
    global stop, procname
    
    procname = 'fetcher'
    setproctitle('netprocess-fetcher')
    last_reported =  time.time() # report to console
    period = 300
    lastloop_started = 0
    deadline = time.time() + lifetime

    cr_cache = crcache.CRCache(get_redis())

    tarpit = dict()

    while not stop:
        
        if time.time() < lastloop_started + sleep:
            sleeptime = sleep - (time.time() - lastloop_started)
            time.sleep( sleeptime )
            cr_cache.r.incr('counter:fetcher_slept')
            cr_cache.r.incrbyfloat('counter:fetcher_slepttime', sleeptime)
        else:
            cr_cache.r.incr('counter:fetcher_not_slept')
            pass

        cr_cache.r.set('fetcher_pid',os.getpid())
        cr_cache.r.expire('fetcher_pid',60)


        lastloop_started = time.time()

        # delete 
        fids = cr_cache.r.hgetall('fids')
        delfids = cr_cache.r.hgetall('delete_fids')
        for fullname in delfids.keys():            
            if fids[fullname] == delfids[fullname]:
                cr_cache.r.hdel('fids', fullname)
            cr_cache.r.hdel('delete_fids', fullname)
        
        nlocked = cr_cache.num_locked()
        nsch = cr_cache.num_scheduled()

        if not stop:                
            can_get = maxsch - nsch        
        else:
            can_get = 0

        if (can_get > 0) and (maxlocked is None or nlocked < maxlocked):
                        
                                        
            for rs in machines:
                # log.debug("{}: fetch from machine {}: {}".format(os.getpid(), rs.name, rs.last_tproc_get))
                
                if rs.name in tarpit:
                    exp = tarpit[rs.name]
                    if time.time() > exp:
                        log.info('release {} from tarpit'.format(rs.name))
                        del tarpit[rs.name]
                    else:
                        continue
                
                qlen = cr_cache.r.scard('machine:{}:q'.format(rs.name))
                if qlen and int(qlen)>100:
                    log.debug(u"skip fetching from {} (qlen: {})".format(rs.name, repr(qlen)))
                    cr_cache.r.incr('counter:{}:fetch_skipped'.format(rs.name))
                    continue
                                
                if not stop:                               
                    # check_process(rs) ??? !!!
                    # log.info("fetcher Q size: {}".format(q.qsize()))
                                        
                    if can_get > 0:
                        cr_cache.r.incr('counter:{}:fetch_called'.format(rs.name))
                        crlist = rs.get_tproc(num = can_get)
                        
                        if rs.last_status_code is None or rs.last_status_code > 500:
                            log.info("tarpit {} for 30s".format(rs.name))
                            tarpit[rs.name] = time.time() + 30
                        
                        # log.debug("got {}/{} tasks".format(len(crlist), can_get))
                        for cr in crlist:
                        
                            if cr_cache.sismember('locked', cr.fullname):
                                log.warn(u"already locked {}".format(cr.fullname))

                            #cr_cache.zrank('sch', "indicator:" + cr.fullname):
                            
                            if cr_cache.zrank('sch', "fetched:" + cr.fullname) is not None:
                                log.warn(u"already scheduled {}".format(cr.fullname))

                                            
                            cr_cache.sadd('locked', cr.fullname)
                            #log.debug("lock {}".format(cr.fullname))
                            # q.put(cr) # will not use queue anymore
                            # store to redis()
                            # log.info('schedule/lock '+cr.fullname)
                            cr.reschedule(when = time.time())
                            recname = make_ihashname(cr.fullname)
                            cr.fetch_id = recname
                                                                                    
                            if cr_cache.r.hexists('fids', cr.fullname):
                                old = cr_cache.r.hget('fids', cr.fullname)
                            else:
                                old=""
                            
                            #log.info('set fetch_id {} ({})'.format(cr.fetch_id, old))
                            cr_cache.r.hset('fids', cr.fullname, cr.fetch_id)

                            cr_cache.store(cr, recname = recname, schedule=True, target='scheduled') 
                            cr_cache.r.incr('counter:fetched')
                            
        else:
            if stop:
                print("skip fetching because stop")
            else:
                print("skip fetching, because already {} locked, {} scheduled ({}/{} max)".format(nlocked, nsch, maxlocked, maxsch))

        
        # gc.collect()
        if time.time() > deadline:
            log.info("Fetcher {} deadline".format(os.getpid()))
            stop = True
    
    cr_cache.r.delete('fetcher_pid')

    

def process_loop_sender(machines, indicator, lifetime):
    global stop, stop_set, procname
    
    started = time.time()    

    procname = 'sender'    
    setproctitle('netprocess-sender')
    # signal.signal(signal.SIGINT, signal.SIG_IGN)

    cr_cache = crcache.CRCache(get_redis())

    
    last_reported = time.time()
    report_period = 300
    counter = 0        
    
    deadline = time.time() + lifetime
    
    
    while True:
    
        # log.debug("sender new iteration")
        
        cr_cache.r.set('sender_pid',os.getpid())
        cr_cache.r.expire('sender_pid',60)
        
        useful = False
        
        for rs in machines:
            # put to queue
            # log.info("sender machine {}".format(rs.name))
            qname = 'machine:'+ rs.name +':q'
            portiond = dict()                        
           
            for recname in cr_cache.r.srandmember(qname, 20):
                try:
                    # log.debug('going to send {}'.format(recname))
                    cr = cr_cache.load(recname)
                    cr_cache.r.srem(qname, recname)
                    cr_cache.r.delete(recname)

                    cr_cache.r.incr('counter:sender:dequeued')
                
                    if not cr_cache.still_actual(cr):
                        cr_cache.r.incr('counter:sender:not_actual')
                        continue                    
                
                    if not cr.fullname in portiond:
                        # simple. just add
                        portiond[cr.fullname] = cr
                        cr_cache.r.incr('counter:sender:submitted')                    

                    else:
                        # collision! resolve
                        if cr.mtime > portiond[cr.fullname].mtime:
                            # replace
                            portiond[cr.fullname] = cr
                        cr_cache.r.incr('counter:sender:not_submitted')

                    #log.info('will report {} fid: {}'.format(
                    #    str(cr), cr.fetch_id))                                                            
                    cr_cache.stage(cr.fullname, "submitted")
                    
                except cr_cache.NoCR as e:
                    log.warn("no such CR: {}".format(str(e)))
                    pass
                    
            portion = portiond.values()            
            
            cr_cache.r.set('counter:sender:sending',len(portion))
            
            if portion:
                log.debug("send {} results to {}".format(len(portion), rs.name))    
                send_start = time.time()
                try:
                    apply_status = rs.send_tproc_results(portion)
                except requests.exceptions.RequestException as e:
                    log.error("send_tproc to {} error: {}".format(rs.name, str(e)))
                    log.warn("reinject {} indicators".format(len(portion)))
                    for cr in portion:
                        cr_cache.r.incr('counter:sender:reinjected')
                        cr_cache.store(cr, make_ihashname(cr.fullname), 
                            target='machine:' + cr.rs_name + ':q')                                                    
                                                
                else:
            
                    send_stop = time.time()
                 
                    for fullname in apply_status:

                        cr = portiond[fullname]
                    
                        useful = True
                        
                        cr_cache.r.incr('counter:sender:updated')
                                                            
                        # log.debug("server: {} {}".format(fullname, apply_status[fullname]))

                        if apply_status[fullname] == "applied":
                            cr_cache.r.incr('counter:sender:applied')
                            
                            if cr.worthcache():
                                cr.last_update = time.time()
                                cr.reborn()
                                cr_cache.store(cr, recname = make_ihashname(cr.fullname), schedule=True, target='scheduled') 
                                cr_cache.r.incr('counter:sender:rescheduled')
                                log.debug('rescheduled {}'.format(cr.fullname))
                            else:
                                cr_cache.r.incr('counter:onetime')
                                # log.info('will delete {} {}'.format(cr.fullname, cr.fetch_id))
                                cr_cache.r.hset('delete_fids', cr.fullname, cr.fetch_id)
                                                            
                        else:
                            cr_cache.r.incr('counter:sender:not_applied')
                            if cr_cache.still_actual(cr):
                                # log.info('will delete {} {}'.format(cr.fullname, cr.fetch_id))
                                cr_cache.r.hset('delete_fids', cr.fullname, cr.fetch_id)
                            else:
                                log.info('will NOT delete not-actual {} {}'.format(cr.fullname, cr.fetch_id))

                        
                        cr_cache.stage(fullname, None)

                        # log.debug('unlock {}'.format(fullname))
                        cr_cache.srem('locked', fullname)

                finally:
                    cr_cache.r.set('counter:sender:sending',0)
        
            else:
                # log.debug('nothing to send to {}'.format(rs.name))
                pass

        if time.time() > last_reported + report_period:
            sequence = [
                'METHOD numerical',
                'DETAILS {}/{} in {:.2f}s'.format(
                    cr_cache.r.get('counter:sender:applied'),
                    cr_cache.r.get('counter:sender:not_applied'), 
                    time.time() - last_reported),
                'STR {}'.format(counter)
                ]
            # oc.runseq( name=iname, sequence = sequence, method='numerical')
            indicator.update(str(counter),
                '{}/{} in {:.2f}s'.format(
                    cr_cache.r.get('counter:sender:applied'),
                    cr_cache.r.get('counter:sender:not_applied'), 
                    time.time() - last_reported),
                )
            
            counter=0
            last_reported = time.time()

        # gc.collect()
        if time.time() > deadline:
            log.info("Sender {} deadline".format(os.getpid()))
            cr_cache.r.delete('sender_pid')
            return
        
        if stop:
            if not cr_cache.scard('locked'):
                log.info("Stop sender (no locked)")
                cr_cache.r.delete('sender_pid')
                return
            else:
                log.info("Sender still working: {} locked".format(cr_cache.scard('locked')))
            
        # cooldown process
        if useful:
            cr_cache.r.incr('counter:sender:not_slept')                    
        else:
            cr_cache.r.incr('counter:sender:slepttime')                    
            time.sleep(1)

def process_loop(machines, checkfilter = None, indicator=None, sleep = 1, workers = 1, maxlocked = 10, maxsch = 10):
    global stop
    
    got_connection = False
    
    while not got_connection:
        try:
            redis_conn = get_redis()
            redis_conn.flushdb()
            got_connection = True
        except redis.exceptions.ConnectionError as e:
            log.warning('fail to connect to redis. {} retry...'.format(str(e)))
            time.sleep(1)

    cr_cache = crcache.CRCache(redis_conn)
             
    processes = {
        'sender': {
            'lifetime': 1800,
            'started': None 
        },
        'fetcher': {
            'lifetime': 600,
            'started': None
        }                
    }
    
     
    c = 0
    # resultsq = mpQueue()
    # tasksq = mpQueue()
   
    signal.signal(signal.SIGINT, sighandler)

    last_reported = time.time()
    last_collect = 0
    period = 300

    setproctitle('netprocess-main')

    # disable cache
    for rs in machines:
        rs.tcache_enabled = False

    #pfetcher = Process(target = process_loop_fetcher, args = (machines, cr_cache, sleep, maxlocked, maxsch))
    #pfetcher.start()            

    #psender = Process(target = process_loop_sender, args = (machines, cr_cache, oc, iname))
    #psender.start()            

    pfetcher = None
    psender = None

    ilaunched = 0

    # log.info('Launched fetcher: {} and sender: {}'.format(pfetcher.pid, psender.pid))

    while True:       
        
        if not stop:
            # restart if needed
            if pfetcher is None or not pfetcher.is_alive():
                if pfetcher:
                    if not processes['fetcher']['started'] is None:
                        # died
                        age = time.time() - processes['fetcher']['started']
                        if age < processes['fetcher']['lifetime']:
                            log.error('ERROR: fetcher died too early! ({:.2f}s)'.format(age))
                    else:
                        log.error('old fetcher {} is dead in time'.format(pfetcher.pid))
                
                pfetcher = Process(target = process_loop_fetcher, args = (machines, sleep, maxlocked, maxsch, processes['fetcher']['lifetime']))                
                pfetcher.start()
                processes['fetcher']['started'] = time.time()
                log.info('(re)started fetcher pid: {}'.format(pfetcher.pid))

            if psender is None or not psender.is_alive():            
                if psender:
                    if not processes['sender']['started'] is None:
                        # died
                        age = time.time() - processes['sender']['started']
                        if age < processes['sender']['lifetime']:
                            log.error('ERROR: sender died too early! ({:.2f}s)'.format(age))
                        else:
                            log.error('old sender {} is dead'.format(psender.pid))

                psender = Process(target = process_loop_sender, args = (machines, indicator, processes['sender']['lifetime']))
                psender.start()                                    
                processes['sender']['started'] = time.time()
                log.info('(re)started sender pid: {}'.format(psender.pid))        
        
        submitted = 0
        
        
        ach = active_children()

        numnew = 2 + workers - len(ach)
        
        if numnew > 0:        
            launched = 0    
            try:
                for cr in cr_cache.get_scheduled(num=numnew, delete=True):
                    submitted += 1
                    if cr.checkfilter(checkfilter):
                        cr_cache.r.incr('counter:main:checkfiltered')

                        qname = 'machine:'+ cr.rs_name +':q'
                        cr_cache.store(cr, make_ihashname(cr.fullname), 
                            target='machine:' + cr.rs_name + ':q')                                                    


                    else:
                        # log.debug('launch {}'.format(cr.fullname))
                        p = Process(target = check1, args = (cr,))
                        p.start()
                        launched += 1
                        ilaunched += 1
                        
                        curcounter = cr_cache.r.incr('counter:launched')

                        # log.info('main launched {} {} (pre: {} cl: {} cl2: {} il: {})'.format(p.pid, cr.fullname, preincrement, curcounter, curcounter2, ilaunched))
                        cr_cache.stage(cr.fullname, "launched")
            except crcache.NoCR as e:
                log.error("!!! CHECK nocr {}".format(str(e)))
            
            if launched:
                # log.debug("launched {} (locked: {})".format(launched, cr_cache.scard('locked')))
                pass

            # print [p.pid for p in active_children()]
            
            # cooldown sleep
            if submitted == 0:
                time.sleep(1)
        else:
            log.debug("cant launch (workers: {}, active: {})".format(workers, len(active_children())))
            time.sleep(1)

        if time.time() > last_reported + period:
            last_reported = time.time()
            log.info("SUM.MAIN.MEMORY: {}".format(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss))


        # join all dead
        if stop and cr_cache.scard('locked') == 0:                    
        
            # shutdown
            log.info('main {} shutdown procedure'.format(os.getpid()))
            
            # wait for sender to finish
            nac = len(active_children())            
            while nac:
                log.debug('wait for {} children'.format(nac))
                # print active_children()
                time.sleep(0.5)   
                nac = len(active_children())
            
            return

        else:
            ch = active_children()
            # log.info("{} processes running".format(len(ch)))

        if time.time() > last_collect + 600:
            gc.collect()
            last_collect = time.time()
            
def find_cluster():
    delay = 10
    try_list = ['http://localhost:8000/', 'http://localhost:80/', 'http://localhost.okerr.com/']
    while True:
        for turl in try_list:
            print("try url", turl)
            url = urllib.parse.urljoin(turl, '/api/listcluster')
            try:
                r = requests.get(url)
            except requests.exceptions.RequestException:
                pass
            else:
                if r.status_code == 200:
                    print("Found ({}) cluster at {}".format(r.status_code, turl))
                    return turl
        print("Not found cluster... Try again in {}s...".format(delay))
        time.sleep(delay)



def main():

    global redis_dbi

    parser = make_argparser()    
    args = parser.parse_args()  
        
    started = time.time()

    check_result.user_agent = user_agent

    
    #oc = okerrclient.OkerrClient()
    #oc.read_config(args.clientconf)
    op = okerrupdate.OkerrProject('okerr', secret='')

    machines = list()

    redis_dbi = args.dbi


    if args.report is not None:
        report(args.report)
        return


    if args.slow:
        args.num = 1
        args.workers = 1
        args.maxlocked = 1
        args.maxsch = 1

        args.sleep = 10


    if args.verbose:
        err = logging.StreamHandler(sys.stderr)
        log.addHandler(err)
        log.setLevel(logging.DEBUG)
        log.debug('Verbose mode')
        op.setlog(log)
    else:
        #err = logging.StreamHandler(sys.stderr)
        #log.addHandler(err)
        pass


    if args.check:
        tproc = dict()
        tproc['cm'] = args.check.split('|')[0]
        tproc['args'] = dict()
        tproc['textid'] = None
        tproc['name'] = None
        tproc['id'] = None

        
        for arg in args.check.split('|')[1:]:
            splitter = shlex.shlex(arg)
            splitter.whitespace = '=' # '= '
            splitter.whitespace_split = True
            spl = list(splitter)
            if len(spl) == 2:            
                argname, argval = spl
            else:
                argname = spl[0]
                argval = ''
        
            tproc['args'][argname] = argval
        
    
        print(json.dumps(tproc, indent=4))
        cr = check_result.from_request(tproc)
        # cr.check()
        try:
            cr.check()
        except Exception as e:
            log.error(u'!!!!!!!: {}'.format(exc2str(e)))
            cr.status = 'ERR'
            cr.details = exc2str(e)
        
        print("dump:")
        print(cr.dump())
        
        return

    # drop privileges
    requid = pwd.getpwnam(args.user).pw_uid
    maingroup = pwd.getpwnam(args.user).pw_gid
    grouplist = os.getgrouplist(args.user, maingroup)

    if os.getuid() != requid:
        if os.getuid() == 0:
            log.info('switch to user {}'.format(requid))
            os.setgroups(grouplist)
            os.setuid(requid)
        else:
            log.warn('cannot switch to user {} id {}, not root ({})'.format(args.name, requid, os.getuid()))

    if args.iname:

        if not args.textid and '@' in args.iname:
            args.iname, args.textid = args.iname.split('@')
            
        if not args.textid:
            log.error('need --textid with --iname')
            return(1)
          
        # set args url
        if not args.url:
            
            args.url = requests.get('https://cp.okerr.com/api/director/{}'.format(args.textid)).text.rstrip()
            log.debug('got url {} from director for {}@{}'.format(args.url, args.iname, args.textid))            
                
        rs = RemoteServer(url = args.url, find=False)
        rs.client_name = args.name
        rs.client_location = args.location        
        rs.headers = headers
        
        tprocs = rs.get_tproc(textid=args.textid, iname=args.iname)                        
        print("process {}@{} from {}".format(args.iname, args.textid, args.url))
        
        cr = tprocs[0]
        
        run_tproc(cr)            

        try:
            apply_status = rs.send_tproc_results([cr])
        except requests.exceptions.RequestException as e:
            log.error("send_tproc to {} error: {}".format(rs.name, str(e)))

        #rs.add_tproc_result(cr)
        #results = rs.send_tproc_results(force=True)
        
        print(json.dumps(apply_status, indent=4))
        return

    if not args.url and not args.cluster:
        args.cluster = [ find_cluster() ]

    if args.url:
        mname = urllib.parse.urlparse(args.url).netloc
        rs = RemoteServer(name = mname, url = args.url, find=False)
        rs.client_name = args.name
        rs.client_location = args.location
        # if args.verbose:
        #    rs.verbose()
        machines.append(rs)
        
    if args.cluster:
        for c in args.cluster:
            lcurl = urllib.parse.urljoin(c, '/api/listcluster')
            try:
                r = requests.get( lcurl , headers=headers)
            except requests.exceptions.ConnectionError as e:
                log.error("Cannot access listcluster at URL {}".format(lcurl))
                sys.exit(1)            
            
            if r.status_code != 200:
                log.error("ListCluster fetch error. code: {} url: {}".format(r.status_code, lcurl))
                sys.exit(1)                
                
            try:
                data = json.loads(r.text)
            except ValueError:
                log.error("ListCluster decode error. code: {} text: {}".format(r.status_code, r.text))
                sys.exit(1)

            log.info("Got cluster ({} items) from {}".format(len(data), c))

            for ci, machine in data.items():
                if machine['netprocess']:
                    rs = RemoteServer(ci = machine['ci'], name = machine['name'], url=machine['url'], find=False)
                    rs.client_name = args.name
                    rs.client_location = args.location
                    machines.append(rs)                
                    # machines.append(urlsrv(srv['machine'], srv['url']))

    for m in machines:
        m.tasks_per_request = args.num

    if args.numi:
        simulate(machines[0], args.numi, args.template, args.status)
        return


    if len(machines) == 0:
        log.error("No machines. Use --url or --cluster")
        sys.exit(1)
        

    log.info('okerr network processor. {}@{} (uid: {} pid: {})'.format(args.name,args.location, os.geteuid(), os.getpid()))

    myindicator = op.indicator("{}:netprocess".format(myname()), method='numerical')
    
    # myindicator_updated = 0


    #
    # MAIN LOOP
    #    
    
    # gc.set_debug(gc.DEBUG_LEAK)

    if args.pool == 'mp':        
        pool_loop(machines, n=args.workers, maxtasksperchild = args.maxtasksperchild, 
            restart_pool = args.restart_pool, force_restart_pool = args.force_restart_pool,
            checkfilter = args.checkfilter, single = args.single, oc=oc, indicator=myindicator)    
    elif args.pool == 'p':
        process_loop(machines, checkfilter = args.checkfilter, indicator=myindicator, sleep = args.sleep, workers = args.workers, maxlocked = args.maxlocked, maxsch = args.maxsch)
    else:
        print("unknown pool method {}, can be mp or th".format(repr(args.pool)))

if __name__ == '__main__':
    django.setup()
    log = logging.getLogger('okerr')                
    main()



