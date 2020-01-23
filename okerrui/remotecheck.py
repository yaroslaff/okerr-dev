import OpenSSL
import ssl
import socket
import datetime
import sys
import hashlib
import requests
import logging
import subprocess
import whois
import dns.resolver
from dns.exception import DNSException
import pyping
import re
import time
import ADNS
import string
import urllib.parse
import shlex
import select

import urllib3
urllib3.disable_warnings()

from forcedip import ForcedIPHTTPSAdapter
### from myutils import forceunicode



class DNSBL:

    """A class for defining various DNS-based blacklists."""

    def __init__(self, name, zone, URL='', results=None):
        """Create a DNS blacklist name, based on the given zone.
        If presently, URL is a template that produces a link
        back to information for a given address. results
        should map returned addresses to list codes."""

        self.name = name
        self.zone = zone
        self.URL = URL
        self.results = {}
        if results:
            for result, name in results.items(): self.result(result, name)

    def result(self, result, name):
        """Add a possible result set."""
        self.results[result] = name

    def getURL(self, ip):
        """Return a URL to information on the list of ip on this
        blacklist."""
        return self.URL.format(ip)
    

class DNSBLQueryEngine(ADNS.QueryEngine):

    def __init__(self, s=None, blacklists=None):
        ADNS.QueryEngine.__init__(self, s)
        self.blacklists = {}
        self.dnsbl_results = {}
        if blacklists:
            for l in blacklists: self.blacklist(l)
            
    def blacklist(self, dnsbl):
        """Add a DNSBL."""
        self.blacklists[dnsbl.name] = dnsbl
        
    def submit_dnsbl(self, qname):
        from adns import rr
        for l, d in self.blacklists.items():
            self.dnsbl_results[qname] = []
            self.submit_reverse_any(qname, d.zone, rr.A,
                                    callback=self.dnsbl_callback,
                                    extra=l)

    def dnsbl_callback(self, answer, qname, rr, flags, l):

        if not answer[0]:
            for addr in answer[3]:
                #self.dnsbl_results[qname].append( 
                #    self.blacklists[l].results.get(addr, "%s-%s"%(l,addr))
                #    )
                
                #print "addr:",addr
                #print "qname:", qname
                #print "rr:", rr
                #print "l:", l
                #print "answer:", answer
                
                # res = "%s=%s" % (l, addr)
                res = rr
                
                self.dnsbl_results[qname].append( (
                    self.blacklists[l].results.get(addr, res),
                    self.blacklists[l].getURL(qname)) )



class check_result(object):    

    user_agent = 'OkerrSensor/0.1'

    def __init__(self, status='OK', details=''):
        self.status = status
        self.oldstatus = None
        self.details = details
        self.set_args = dict()
        self.args = dict()
        self.msgtags = dict()
        self.logs = list()
        self.alerts = list()
        self.id = None
        self.name = None
        self.textid = None
        self.mtime = 0
        self.period = 0
        self.last_update = 0.0  # last time sent update to server
        self.throttle = 300      # how often sent updates (even if nothing changed)
        self.scheduled = 0.0
        self.problem = False
        self.fetch_id = None

        self.code = None

        # self.user_agent = 'remotecheck'

        self.allfields = [
            "name", "textid", "fullname", "fetch_id",
            "cm", "args", 
            "status", "details", "oldstatus",
            "mtime", "rs_url", "rs_name",
            "set_args","problem","logs","alerts",
            "code", "msgtags",
            "period","scheduled","last_update","throttle"
            ]

    def __str__(self):
        return u"{}@{} = {} ({})".format(self.name, self.textid, self.status, self.details)
    
        out = ''
        for f in self.__dict__:
            if self.__dict__[f]:
                out += '{} = {}\n'.format(f, self.__dict__[f]) 
        return out
    
    def data(self):
        return self.__dict__
    
    def reborn(self):
        self.reschedule()
        self.msgtags = dict()
        self.oldstatus = self.status
        self.alerts = list()
        self.set_args = dict()
        self.logs = list()
    
    @staticmethod
    def from_request(r,rs_url=None, rs_name=None):
        cr = check_result()
        for attr in ['textid', 'name', 'period', 'throttle', 'mtime', 'cm', 'args']:
            if attr in r:
                setattr(cr,attr,r[attr])

        for attr in ['name', 'textid']:
            # setattr(cr, attr, forceunicode(r[attr]))
            setattr(cr, attr, str(r[attr]))

        # cr.fullname = u'{}@{}'.format(forceunicode(cr.name), forceunicode(cr.textid))
        cr.fullname = u'{}@{}'.format(str(cr.name), str(cr.textid))

        if rs_url:
            cr.rs_url = rs_url

        if rs_name:
            cr.rs_name = rs_name

        cr.oldstatus = None
        cr.last_update = 0
        return cr        
    
    #
    # convert to dict for api_tproc_set
    #
    def response(self):
        r = dict()
        for field in ['name', 'textid', 'status', 'details', 'set_args','logs','alerts','mtime','problem','code']:
            r[field] = getattr(self,field)
            
        # make code message
        r['code_message'] = ''.join(["["+k+"]" for k in self.msgtags.keys()])      
        return r
    
    def serialize(self):
            
        d = dict()
        for field in self.allfields:
            if hasattr(self, field):
                d[field] = getattr(self, field)
        return d
    
    def reschedule(self, when = None):
        if when is None:
            when = time.time() + self.period
        
        self.scheduled = when

    def worthcache(self):
        return self.period <= 1800

    def suppress(self):
        # print "suppress? {} {}:{} last: {:.2f} throttle: {} ({:.2f}s left)".format(self, self.status, self.oldstatus, self.last_update, self.throttle, self.last_update + self.throttle - time.time())
        
        if self.status != self.oldstatus:
            # print "changed status"
            return False        
        
        if time.time() > self.last_update + self.throttle:
            # print "time passed (throttle: {})".format(self.throttle)
            return False

        if self.alerts:
            #print "have alerts"
            return False
        
        # print "suppress ({}s left)".format(int(self.last_update + self.throttle - time.time()))
        return True
                    
    def set_arg(self, argname, argval):
        self.set_args[argname]=argval
        self.args[argname]=argval
        
    def log(self, msg):
        self.logs.append(msg)

    def alert(self, msg):
        self.alerts.append(msg)


    def checkfilter(self, checkfilter):
        try:
            if 'nosmtp' in checkfilter:
                ports = [25, 465, 587]
                if self.cm in ['sslcert', 'tcpport'] and int(self.args['port']) in ports:
                    # dont check it
                    self.code = 501
                    self.msgtags["nosmtp:{}".format(self.args['port'])] = 1
                    return True                 
            if 'noroot' in checkfilter:
                if self.cm in ['ping']:
                    self.code = 501
                    self.msgtags["noroot"] = 1
                    return True                                                     
            return False
        except Exception as e:
            print("checkfilter exception:",str(e))
            self.code = 502
            self.msgtags["checkfilter:exception"] = 1
            return True

    def dump(self):
        print(self)


    def rget(self, url, options='', allow_redirects=True):

        verify = True
        headers = {
            'User-Agent': self.user_agent
        }
        
        
        url_parsed = urllib.parse.urlparse(url)
        url_scheme = url_parsed.scheme
        if ':' in url_parsed.netloc:
            url_host = url_parsed.netloc.split(':')[0]
        else:
            url_host = url_parsed.netloc
        
        
        o = dict()
        for s in shlex.split(options):
            if '=' in s:
                k,v = s.split('=',1)
                o[k]=v
            else:
                o[s]=True
                
        if 'ssl_noverify' in  o:
            verify = False
        
        session = requests.Session()
        if 'addr' in o:
        
            if url_scheme == 'https':
                session.mount(url, ForcedIPHTTPSAdapter(dest_ip=o['addr']))
            else:
                # http                
                url_changed = url_parsed._replace(netloc = o['addr'])
                headers['Host'] = url_host
                url = urllib.parse.urlunparse(url_changed)
        
        r = session.get(
            url, verify=verify, headers=headers, allow_redirects = allow_redirects)
        return r

    def check(self):
        
        actions = {
            'sslcert':      self.action_sslcert,
            'sha1static':   self.action_sha1static,
            'sha1dynamic':  self.action_sha1dynamic,
            'ping':         self.action_ping,
            'httpgrep':     self.action_httpgrep,
            'httpstatus':   self.action_httpstatus,
            'tcpport':      self.action_tcpport,
            'whois':        self.action_whois,
            'dns':          self.action_dns,
            'dnsbl':        self.action_dnsbl
        }


        
        if self.cm in actions:
            self.code = None
        
            actions[self.cm]()
            
            if self.code is None:
                # set default success code
                self.code = 200
                self.msgtags['CHECKED']=1
                        
        else:
            print("ERROR !!! dont know how to handle", repr(self.cm))
            sys.exit(1)        

    def action_httpstatus(self):
    
               
        url = self.args.get("url",'http://okerr.com/')
        options = self.args.get("options",'')
        required_status = int(self.args.get("status", 200))

        try:
        
            r=self.rget(url, options = options, allow_redirects=False)

            if r.status_code == required_status:
                # good, status as it should be
                self.details="Got status code {} as expected".format(required_status)
                self.status="OK"
            else:
                self.details="Bad status code {} (expected {})".format(r.status_code,required_status)
                self.status="ERR"
        except requests.exceptions.RequestException as e:
            self.details="Cannot perform request URL {}: {}".format(url, e)
            self.status="ERR"


    def action_sslcert(self):

        CA_CERTS = "/etc/ssl/certs/ca-certificates.crt"

        #
        # get cert and return notAfter (datetime), NO verification
        #
        def nafter_noverify(addr, host,port,options):
               
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((addr, port))

            ctx = ssl._create_unverified_context()
            ctx.verify_mode = ssl.CERT_NONE
            
            sslsock = ctx.wrap_socket(
                sock,
                server_hostname = host,
                # cert_reqs = ssl.CERT_NONE,
                )
                    
            cert = sslsock.getpeercert(True)
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
            
            m = re.match('(\d+)', x509.get_notAfter().decode('ascii'))
            if m:
                nafterstr = m.group(0)
            else:
                log.error("Cannot parse notAfter for {}:{}! '{}'".format(host,port,x509.get_notAfter().decode('ascii')))

            cert_nafter = datetime.datetime.strptime(nafterstr, '%Y%m%d%H%M%S')

            sock.close()
            sslsock.close()

            return cert_nafter

        #
        # get cert and return notAfter (datetime), verification
        #
        def nafter_verify(addr, host,port,options):

            ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'    
               
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((addr, port))
            
            # !!! TODO FIXME check with wrong hostname (throws exception)
            ctx = ssl.create_default_context()
            sslsock = ctx.wrap_socket(
                sock,
                server_hostname = host,
                )
                    
            cert = sslsock.getpeercert()


            ssl.match_hostname(cert,host)
            nafterstr = cert['notAfter']                  
            cert_nafter = datetime.datetime.strptime(nafterstr, ssl_date_fmt)
            
            sock.close()
            sslsock.close()
            return cert_nafter


        
        def certnames(cert):
            names=[]
            
            if 'subject' in cert:
                for subj in cert['subject']:
                    if subj[0]=='commonName':
                        names.append(subj[1])


            if 'subjectAltName' in cert:
                for san in cert['subjectAltName']:
                    if san[0]=='DNS':
                        names.append(san[1])
            return names        


        try:
            host = self.args.get('host', 'okerr.com')
            port = self.args.get('port', '443')
            days = self.args.get('days', 20)
            options = self.args.get('options','')    
        except KeyError as e:
            self.status = 'ERR'
            self.details = str(e)
            return


        o = dict()
        for s in shlex.split(options):
            if '=' in s:
                k,v = s.split('=',1)
                o[k]=v
            else:
                o[s]=True

        if 'addr' in o:
            addr = o['addr']
        else:
            addr = host

        try:
            port = int(port)
            days = int(days)
        except ValueError as e:
            self.status = 'ERR'
            self.details = str(e)
            return

        try:
            
            if 'noverify' or 'ssl_noverify' in o:
                cert_nafter = nafter_noverify(addr, host, port, options)
            else:
                cert_nafter = nafter_verify(addr, host, port, options)

                        
            cur_date = datetime.datetime.utcnow()
                        
            #cert_nafter = datetime.datetime.strptime(cert['notAfter'], ssl_date_fmt)

            expire_days = int((cert_nafter - cur_date).days)

        except (socket.gaierror, socket.timeout, socket.error) as e:                
            self.details = 'socket error: {}'.format(str(e))                
            self.status = "ERR"
                                
            # add details if this is hostname
            
            try:
                socket.inet_aton(host)
            except socket.error:          
                # this is hostname
                ips = list()
                my_resolver = dns.resolver.Resolver()
                try:
                    answer = my_resolver.query(host, 'a')
                    for rr in answer.rrset:
                        ips.append(rr.address)
                except DNSException:
                    return 
                self.details += ' (DNS: {})'.format(' '.join(ips))
            return
            
        except (ssl.CertificateError, ssl.SSLError) as e:
            self.details = 'SSL error: {}'.format(str(e))
            self.status = "ERR"
            return 
            
        self.details = "{} days left".format(expire_days)
        if expire_days > days:
            self.status = "OK"
        else:
            self.status = "ERR"







    def action_sha1static(self):
        url = self.args.get("url", 'http://okerr.com/')                
        pagehash = self.args.get("hash",'')
        options = self.args.get("options",'')
        setargs = dict()

        try:
            r=self.rget(url, options)
           
            if r.status_code != 200:
                self.status = "ERR"
                self.details = "Status code: {} (not 200)".format(str(r.status_code))
                return

            realhash = hashlib.sha1(r.content).hexdigest()
            # check if it has musthave
            if len(pagehash)==0:
                self.status = "OK"
                self.details = "hash initialized"
                self.set_arg("hash",realhash)
                return 
            else:                    
                if realhash==pagehash:
                    self.details = "hash match"
                    self.status = "OK"
                    return
                else:
                    self.details = "hash mismatch"
                    self.status = "ERR"
                    return
        
        except requests.exceptions.RequestException as e:
            self.details = "exception: {}".format(e)
            self.status = "ERR"


    def action_sha1dynamic(self):
        url = self.args.get("url",'http://okerr.com/')                
        pagehash = self.args.get("hash",'')
        options = self.args.get("options",'')

        try:
            r=self.rget(url, options = options)

            if r.status_code != 200:
                return check_result("ERR","Status code: {} (not 200)".format(str(r.status_code)))

            realhash = hashlib.sha1(r.content).hexdigest()
            # check if it has musthave
            if len(pagehash)==0:
                self.status = "OK"
                self.details = "hash initialized"
                self.set_arg("hash", realhash)
                return 
            else:
                if realhash == pagehash:
                    self.status = "OK"
                    self.details = "hash match"
                    return 
                else:
                    # send alert from here, because we return OK !!!!
                    self.status = "OK"
                    self.details = "new hash"
                    self.set_arg("hash",realhash)
                    self.alert("Page {url} changed hash from {old} to {new}".format(url=url,old=pagehash,new=realhash))
                    return
        
        except requests.exceptions.RequestException as e:
            self.status = "ERR"
            self.details = "exception: {}".format(e)


    def action_ping(self):

        try:
            r = pyping.ping(self.args["host"])
        except Exception as e:
            self.status = "ERR"
            self.details = str(e)
            return 

        self.details = "{} ({}) rtt: {}/{}/{} lost: {}".format(r.destination, r.destination_ip, r.min_rtt, r.avg_rtt, r.max_rtt, r.packet_lost)
        
        # log.debug(self.details)
                    
        if r.ret_code == 0:
            self.status = "OK"
        else: 
            self.status = "ERR"


    def action_tcpport(self):    
        host = self.args["host"]
        port = int(self.args["port"])
        substr = self.args["substr"]
        timeout=2
        
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            self.status = "ERR"
            self.details = "cannot resolve {}".format(host)
            return
            
        try:
            c = socket.create_connection((ip,port), 2)
            if len(substr)>0:
                c.setblocking(0)

                ready = select.select([c], [], [], timeout)
                if ready[0]:
                    data = c.recv(4096).decode('utf8')
                    pos = data.find(substr)
                    data = re.sub("[\r\n]","",data) # delete newlines

                    if len(data)>20:
                        preview = data[:20]+'...'
                    else:
                        preview = data

                    if pos<0:
                        self.status = "ERR"
                        self.details = "Not found substr '{}' in banner '{}'".format(substr, preview)
                        return 
                    else:
                        self.status = "OK"
                        self.details = "Found substr '{}' in banner '{}'".format(substr, preview)
                        return
                else:
                    self.status = "ERR"
                    self.details = "Did not get banner"
                    return
            else:
                self.status = "OK"
                self.details = "Connected to {host}:{port} at {ip}".format(host=host,port=port,ip=ip)
                return 
            
        except socket.error:
            self.status = "ERR"
            self.details = "failed to connect to {host}:{port} at {ip}".format(host=host,port=port,ip=ip)
            return



    def action_httpgrep(self):
        url = self.args.get("url",'')
        musthave = self.args.get("musthave",'')
        mustnothave = self.args.get("mustnothave",'')
        options = self.args.get("options",'')


        try:
            r=self.rget(url, options)

            if r.status_code != 200:
                self.status = "ERR"
                self.details = "Status code: {} (not 200)".format(str(r.status_code))
                return

            ucontent = r.content.decode('utf8')

            # check if it has musthave
            if len(musthave)>0:
                if ucontent.find(musthave)==-1:
                    self.status = "ERR"
                    self.details = u"Content has no substring '{}'".format(musthave)
                    return

            if len(mustnothave)>0:
                if ucontent.find(mustnothave)>=0:
                    self.status = "ERR"
                    self.details = "Content has substring '{}'".format(mustnothave)
                    return
            
            self.status = "OK"
            self.details = ""
            return
        
        except requests.exceptions.RequestException as e:
            self.status = "ERR"
            self.details = "Cannot perform request URL {}: {}".format(url, e)
            return



    def action_whois(self):
        domain = self.args["domain"]
        days = int(self.args["days"])

        w = whois.whois(domain)

        today = datetime.datetime.now()
            
        exp = w.expiration_date
        
        if exp is None:
            self.status = "ERR"
            self.details = "whois error"
            return 
        
        if isinstance(exp, list):
            exp = exp[0]
        
        left = exp - today

        leftdays = left.days

        self.details = str("{} days left".format(leftdays))
        
        if leftdays < days:        
            self.status = 'ERR'
        else:
            self.status = 'OK'
                



    def action_dns(self):
        host = self.args.get("host")
        qtype = self.args.get("type")
        options = self.args.get("options")
        value = self.args.get("value")
        

        resolver = dns.resolver.Resolver()
        resolver.search = None    
        

        try:
            
            # DNSBL part
            if qtype.lower().startswith("dnsbl"):
                
                # args["host"] = '1.2.3.4'
                dnsbl, blsuffix = qtype.split()

                if not blsuffix.endswith('.'):
                    blsuffix = blsuffix + '.'

                # resolve host to IP first
                ip4 = socket.gethostbyname(host)
                
                qhost = '.'.join(reversed(ip4.split('.'))) + '.'+blsuffix
                
                try:
                    answers = resolver.query(qhost, 'A')
                except dns.resolver.NXDOMAIN:
                    # great! not found in blacklist
                    self.status = "OK"
                    self.details = "{} ({}) not in {}".format(host, ip4, blsuffix) 
                    return

                # bad. we are in list!                
                self.set_arg('value', str(answers[0]))
                self.status = "ERR"
                self.details = str(resolver.query(qhost, 'TXT')[0])
                return

        
            # COMMON PART            
            if qtype.lower() == "reverse":
                host = dns.reversename.from_address(host)
                qtype = 'PTR'

            answers = resolver.query(host, qtype)
            dnsstr = ' '.join(sorted( str(a) for a in answers ))
                    
            # initialization?
            if value == '' and 'init' in options:
                self.set_arg("value",dnsstr)
                self.status = "OK"
                self.details = "init: {}".format(dnsstr)            
                return
            
            if dnsstr == value:
                self.status = "OK"
                self.details = "match: {}".format(dnsstr)
                return 
            
            # value mismatch
            if 'dynamic' in options:
                self.status = "OK"
                self.details = "new: {}".format(dnsstr)
                self.set_arg("value",dnsstr)
                self.alert("{} > {}".format(value, dnsstr))
                return
            
            self.status = "ERR"
            self.details = dnsstr
            return 

        except dns.rdatatype.UnknownRdatatype as e:
            log.debug("Exception {} {}".format(type(e), str(e)))
            self.status = "ERR"
            self.details = str(e)
            self.problem = True
            return 
            
        except Exception as e:
            log.debug("Exception {} {}".format(type(e), str(e)))
            self.status = "ERR"
            self.details = str(e)
            return

    def action_dnsbl(self):
        host = self.args["host"]
        skip = self.args["skip"]
        extra = self.args["extra"]

        skip_dnsbl = filter(None, re.split('[, ]+', skip))
        extra_dnsbl = filter(None, re.split('[, ]+', extra))

        resolver = dns.resolver.Resolver()
        resolver.search = None    

        ips = list()
        
        try:            
            socket.inet_aton(host)
            ips.append(host)
        except socket.error:
            try:
                answers = resolver.query(host, 'A')
                
                for ans in answers:
                    ips.append(str(ans))
                
            except dns.resolver.NXDOMAIN:                
                self.status = "ERR"
                self.details = "NXDOMAIN {}".format(host)                
                return

            except dns.resolver.Timeout:                
                self.status = "ERR"
                self.details = "TIMEOUT {}".format(host)                
                return


        
        bl_zones = [
            'cbl.abuseat.org',
            'dnsbl.sorbs.net',
            'dul.dnsbl.sorbs.net',
            'smtp.dnsbl.sorbs.net',
            'spam.dnsbl.sorbs.net',
            'zombie.dnsbl.sorbs.net',
            'sbl.spamhaus.org',
            'zen.spamhaus.org',
            'psbl.surriel.com',
            'rbl.spamlab.com',
            'noptr.spamrats.com', 
            'cbl.anti-spam.org.cn', 
            'dnsbl.inps.de', 
            'httpbl.abuse.ch', 
            'short.rbl.jp', 
            'spamrbl.imp.ch', 
            'virbl.bit.nl', 
            'dsn.rfc-ignorant.org', 
            'opm.tornevall.org', 
            'multi.surbl.org', 
            'tor.dan.me.uk', 
            'relays.mail-abuse.org', 
            'rbl-plus.mail-abuse.org', 
            'access.redhawk.org', 
            'rbl.interserver.net', 
            'bogons.cymru.com', 
            'truncate.gbudb.net', 
            'bl.spamcop.net', 
            'b.barracudacentral.org', 
            'http.dnsbl.sorbs.net', 
            'misc.dnsbl.sorbs.net', 
            'socks.dnsbl.sorbs.net', 
            'web.dnsbl.sorbs.net', 
            'pbl.spamhaus.org', 
            'xbl.spamhaus.org', 
            'ubl.unsubscore.com', 
            'dyna.spamrats.com', 
            'spam.spamrats.com', 
            'cdl.anti-spam.org.cn', 
            'drone.abuse.ch', 
            'korea.services.net', 
            'virus.rbl.jp', 
            'wormrbl.imp.ch', 
            'rbl.suresupport.com', 
            'spamguard.leadmon.net', 
            'netblock.pedantic.org', 
            'ix.dnsbl.manitu.net', 
            'rbl.efnetrbl.org', 
            'blackholes.mail-abuse.org', 
            'dnsbl.dronebl.org', 
            'db.wpbl.info', 
            'query.senderbase.org', 
            'csi.cloudmark.com',

            # 'bl.spamcannibal.org', 
            # 'combined.njabl.org', 
            # 'dnsbl.njabl.org',

        ]
        
                
        blacklists = list()                        

        checked = 0
        
        for bl in bl_zones:
            if not bl in skip_dnsbl:                
                blacklists.append(DNSBL(name=bl, zone=bl))
                checked += 1
            else:
                # print "skip", bl[0]                                    
                pass

        for bl in extra_dnsbl:
            blacklists.append(DNSBL(name=bl, zone=bl))
            checked += 1

        s = DNSBLQueryEngine(blacklists=blacklists)
        for ip in ips:
            s.submit_dnsbl(ip)            
        s.finish()
        listed = s.dnsbl_results
        
        for k, v in listed.items():
            hits = []
            for l, url in v: 
                hits.append(l)

        if hits:
            self.status = "ERR"
            self.details = "{} (total: {}/{})".format(', '.join(hits[:3]), len(hits), checked)
            return
        else:
            self.status = "OK"
            self.details = "Not found in {} DNSBL checked".format(checked)
            

    __repr__ = __str__
        
        
# main
log = logging.getLogger('okerr')                
        
