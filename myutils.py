#!/usr/bin/env python

import os
import sys
import django
import pytz
from pytz import reference
import datetime
import time
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "okerr.settings")
from django.conf import settings
from django.utils import timezone
from django.core.mail import EmailMultiAlternatives
from django.utils.translation import get_language as django_get_language

import requests

import string
import fcntl
import re
import redis
import inspect
import socket

import dns.resolver
from dns.exception import DNSException

import traceback
import logging
import logging.handlers

def get_verified_reverse(ip):

    try:
        reverse, aliases, ipaddrs = socket.gethostbyaddr(ip)  # getfqdn need for charlie > charlie.okerr.com

        reverse = socket.getfqdn(reverse)  # add optional domain

        # verify!
        hname, aliases, addresses = socket.gethostbyname_ex(reverse)

        if ip in addresses:
            return reverse

    except Exception:
        return None

    return None



def md_escape(txt):
    escape = '\\`*_#!'
    #escape = '\\`*_{}[]()#+-.!'
    for ch in escape:    
        txt = txt.replace(ch, '\\' + ch)
    return txt


def timesuffix2sec(timesuffix):
    suf = { 's':1, 'm': 60, 'h': 3600, 'd': 86400 }


    r = re.match('(\d+)(h|m|s|hour|hours|hr|min|minute|minutes|sec|seconds)?$',timesuffix)
    if r is None:
        raise ValueError('Cannot parse \'{}\'. Valid examples are: 10s, 5m, 2h'.format(timesuffix))

    r = re.match('(\d+)([hmsHMS])?',timesuffix)
    if r is None:
        raise ValueError('Bad time/suffix value {}'.format(timesuffix))
        
    n = int(r.group(1))
    try:
        suffix = r.group(2).lower()
    except:
        suffix='s'
    return n * suf[suffix]


# string to datetime (str is '2d1h30m14s' or 3600)
def str2dt(s):
    
    if isinstance(s, int):
        return datetime.timedelta(seconds=s)

    dt = datetime.timedelta(seconds=0)

    m = re.search('(\d+)s?$',s)
    if m:
        dt += datetime.timedelta(seconds=int(m.group(1)))

    m = re.search('(\d+)m',s)
    if m:
        dt += datetime.timedelta(minutes=int(m.group(1)))

    m = re.search('(\d+)h',s)
    if m:
        dt += datetime.timedelta(hours=int(m.group(1)))

    m = re.search('(\d+)d',s)
    if m:
        dt += datetime.timedelta(days=int(m.group(1)))


    return dt


def lockpidfile(filename):
    fp = open(filename, 'w')
    try:
        fcntl.lockf(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fp.write(str(os.getpid()))
        fp.flush()
        return fp
    except IOError:
        return None

def UNUSED_forceunicode(value):
    if value is None:
        return None
        
    if not isinstance(value, basestring):
        value = unicode(value,'utf-8')
    if not isinstance(value, unicode):
        value = value.decode('utf8')
    return value

def forcestr(value):
    if not isinstance(value, basestring):
        value = str(value)
    if isinstance(value, unicode):
        value = value.encode('utf8')
    return value


def pointchange(old,new):
    def char(ch):
        if ch in string.printable and not ch in string.whitespace:
            print('char "{}" printable'.format(ch))
            return '\'{}\''.format(ch)
        else:
            return '#{}'.format(ord(ch))

    for t in zip(old,new,range(max(len(old),len(new)))):
        if t[0]!=t[1]:
            return "pos {} ch {} {}".\
                format(t[2],char(t[0]),char(t[1]))


def strdiff(old,new,sepstr=' ,:|'):

    # print "try str, sep: {}".format(repr(sepstr))

    def hasdups(l):
        for i in l:
            if l.count(i)>1:
                return True
        return False

    diffs={}
    # first, try to guess separator

    for sep in sepstr:
        # print("try separator '{}'".format(repr(sep)))
        olda = old.split(sep)
        newa = new.split(sep)
        
        # print("olda {} items, newa {} items".format(len(olda),len(newa)))
        
        if hasdups(newa) or hasdups(olda):
            # bad separator
            # print "bad separator"
            continue
        
        diffs[sep]={}
        diffs[sep]['old']=olda
        diffs[sep]['new']=newa
        diffs[sep]['oldn']=len(olda)
        diffs[sep]['newn']=len(newa)
        
    for sep,diff in diffs.items():

        score=0

        diff['+']=[]
        diff['-']=[]

        for i in diff['old']:
            if not i in diff['new']:
                diff['-'].append(i) 
                score+=len(i)

        for i in diff['new']:
            if not i in diff['old']:
                diff['+'].append(i) 
                score+=len(i)
        diff['score']=score        

    bestsep=None
    bestscore=None
 
    for sep,diff in diffs.items():
        if bestsep is None or diff['score']<bestscore:
            # init
            bestsep=sep
            bestscore=diff['score']

    if bestscore>=len(old) or bestscore>=len(new) or bestscore==0:
        return None

    return diffs[bestsep]['+'],diffs[bestsep]['-']
 


def mybacktrace(maxdepth=3):
    depth=0
    stack=inspect.stack()
    stack.pop(0) # remove inspect
    stack.pop(0) # remove mybacktrace
    for s in stack:
        print("{prefix}{filename}:{line} {function} {code}".format(
            prefix="  "*depth,
            filename=os.path.basename(s[1]),
            line=s[2],function=s[3],code=s[4]
            ))
        depth+=1
        if depth>maxdepth:
            return


def UNUSED_remoteaddr(request):
    remote=request.META.get('REMOTE_ADDR')
    return remote


def get_remoteip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip



def openlog():
#    logging.basicConfig(level=logging.DEBUG, format='OKERR %(message)s')
    log = logging.getLogger('MyLogger')
    log.setLevel(logging.DEBUG)
    # handler = logging.handlers.SysLogHandler(address = '/dev/log', facility=logging.handlers.SysLogHandler.LOG_LOCAL1)
    handler = logging.StreamHandler(sys.stdout)
    log.propagate = False
    log.addHandler(handler)
    return log


def chopms(dt):

    if isinstance(dt,datetime.datetime):
        return dt-datetime.timedelta(microseconds=dt.microsecond)
    elif isinstance(dt,datetime.timedelta):
        return dt-datetime.timedelta(microseconds=dt.microseconds)
    else:
        # ERROR: chopms for unhandled type
        raise ValueError(
            'chopms called with bad type {} instead of '\
            'datetime or timedelta'.format(type(dt)))


def shorttd(td, npos=2):
    """
    short timedelta representation
    """

    seconds = int(td.total_seconds())
    periods = [
        ('days ', 60 * 60 * 24),
        ('h', 60 * 60),
        ('m', 60),
        ('s', 1)
    ]

    strings = []
    for period_name, period_seconds in periods:
        if seconds > period_seconds:
            period_value, seconds = divmod(seconds, period_seconds)
            strings.append("%s%s" % (period_value, period_name))
            npos -= 1
            if npos == 0:
                break

    return "".join(strings)


def shorttime(dt):
    if dt is None:
        return None
    else:
        return dt.strftime('%H:%M:%S')

def shortdate(dt=None,tzname=None):
    if not dt:
        dt = timezone.now()
    if tzname:
        localtz=pytz.timezone(tzname)
        if localtz:
            return dt.astimezone(localtz).strftime("%Y/%m/%d %H:%M:%S (%Z)")
        else:
            return "no local tz found"
    else:
        return dt.strftime("%Y/%m/%d %H:%M:%S (%Z)")    

def dhms(sec, sep=" "):
    out=""
    added=0
    t={'d': 86400,'h': 3600,'m': 60,'s': 1}
    
    if isinstance(sec, datetime.timedelta):
        sec = sec.total_seconds()

    for k in sorted(t,key=t.__getitem__,reverse=True):
        
        if added==2:
            return out.rstrip()
        
        if sec>=t[k] or t[k]==1:
            n = int(sec/t[k])
            sec-=n*t[k]
            out+="%d%s%s" % (n,k,sep)
            added += 1
    return out.rstrip()


def shortstr(string,maxsz=40):
    if len(string)<=maxsz:
        return string
        
    # generate suffix
    suffix = ".. ({})".format(len(string))
    first = maxsz-len(suffix)
    if first<10:
        first=10
    
    return string[:first]+suffix

# prefixes iterator
class prefixes:
    def __init__(self, string, sep=':'):
        self.string = string
        self.prefix = ''
        self.sep = sep
         
    def __iter__(self):
        return self

    def __next__(self): # Python 3: def __next__(self)
        if self.string:
            try:
                (element,self.string) = self.string.split(self.sep, 1)
                
                # add prefix 
                if self.prefix:
                    self.prefix = self.sep.join([self.prefix, element])
                else:
                    self.prefix = element
                    return element
               
                # concatenate
                full = self.sep.join([self.prefix,element]) 
                return self.prefix
            except ValueError:
                raise StopIteration
        else:
            raise StopIteration


def unixtime2dt(unixtime):
    if unixtime is None:
        return None
    return datetime.datetime.fromtimestamp(int(unixtime), pytz.utc)

def dt2unixtime(dt):
    if dt is None:
        return None
    return int(time.mktime(dt.timetuple())) 

def send_email(to_addr, from_addr=None, from_name=None, to_name=None, subject='no subject', what='mail', html=None, text=None):

    def should_send(email, recipients):
        if '*' in recipients:
            return True
            
        for r in recipients:        
            if r.startswith('@') and email.endswith(r):
                return True
            else:
                if r==email:
                    return True
        return False

    if not from_addr:
      from_addr = 'noreply@okerr.com'

    if not from_name:
      from_name = 'okerr robot'
 
 
    if not to_name:
        to_name = to_addr
    
    if text is None:
        text=''

    log = logging.getLogger('okerr')                
    

    if should_send(to_addr, settings.MAIL_RECIPIENTS):
        log.info('send {} ({}) to {}'.format(what, settings.MYMAIL_METHOD, to_addr))
        
        # plain SMTP sending
        headers = {
            'IsTransactional': 'True'
        }
        # log.info('send to {}, headers: {}'.format(to_addr, headers))
        msg = EmailMultiAlternatives(subject, text, from_addr, [to_addr], headers=headers)
        if html:
            msg.attach_alternative(html, "text/html")
        if text:
            msg.attach_alternative(text, "text/plain")

        msg.send()


    else:
        log.info('skip sending {} to {}, because not in MAIL_RECIPIENTS: {}'.format(what, to_addr, settings.MAIL_RECIPIENTS))
        

def exc2str(e):
    exc_type, exc_obj, exc_tb = sys.exc_info()
    #traceback.print_tb(exc_tb)
    place = traceback.extract_tb(exc_tb)[-1]
    fname = os.path.basename(place[0])
    return "{}:{} {}(): {} | {}: {}".format(fname, place[1], place[2], place[3], exc_type.__name__, str(e))

def strcharset(s, charset):
    for ch in s:
        if not ch in charset:
            return False
    return True

def nsresolve(hostname, ns=None, qtype='a'):
    ips = list()
    my_resolver = dns.resolver.Resolver()
    if ns:
        my_resolver.nameservers = [ns]
    try:
        answer = my_resolver.query(hostname, qtype)
        for rr in answer.rrset:
            ips.append(rr.to_text())
        return ips
    except DNSException:
        return None

def unused_myip():
    url = 'https://diagnostic.opendns.com/myip'

    while True:
        try:
            r = requests.get(url)
        except requests.exceptions.RequestException:
            time.sleep(1)
            pass
        if r.status_code == 200:
            return r.text
        else:
            time.sleep(5)


def get_redis(dbindex=0):
    if 'REDIS_HOST' in os.environ:
        return redis.Redis(host=os.environ['REDIS_HOST'], port=6379, db=dbindex)
    else:    
        rsocks = ['/var/run/redis/redis-server.sock', '/var/run/redis/redis.sock']
        for rs in rsocks:
            if os.path.exists(rs):
                return redis.Redis(unix_socket_path=rs, decode_responses=True, db=dbindex)

    # no var, no socket. maybe localhost?
    return redis.Redis(host='127.0.0.1', port=6379, db=dbindex)

    

if __name__ == '__main__':
    django.setup()        
    print(shortdate(timezone.now(),"Asia/Novosibirsk"))





