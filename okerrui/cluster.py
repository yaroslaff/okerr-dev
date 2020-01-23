import socket
from django.conf import settings
#from django.core.urlresolvers import reverse
from django.urls import reverse

import sys
import urllib.parse
import requests
import json
import time
import logging

from okerrui.remotecheck import check_result


# log = logging.getLogger('okerr')                


class RemoteServer():
    
    _skip = list()
    
    def __init__(self, ci=None, url=None, name=None, find=True):

        # get machine structure from args
    
        if find:
            machine = RemoteServer.get_machine(ci = ci, url = url, name = name)

            assert machine is not None        
            
            for attr in ['ci','name','url','netprocess']:
                setattr(self, attr, machine[attr])
        else:
            self.ci = ci
            self.name = name
            self.url = url
        
        self.log = logging.getLogger('okerr')
        
        self.client_name = 'unknown_name'
        self.client_location = 'unknown_location'
        self.headers = None

        self.last_status_code = None        
        
        # time, rate-limit
        self.last_tproc_get = 0 # unixtime when we last time called /api/tproc_get
        self.last_tproc_set = 0 # unixtime when we last time called /api/tproc_set
        self.oldest_tproc_add = 0 # EARLIEST checkresult in queue
        
        self.tproc_period = 1
        self.last_check_process = 0
        self.last_check_process_alert = 0
        
        self.tasks_per_request = 50 
        
        # counters
        self.tproc_updated = 0
        
        # cached (but not sent) tproc_results
        self.tproc_results = list()
    
        self.tcache_enabled = True # set False to disable
        # self.tcache = TaskCache()
                
        self.cache = dict()                
        
        # fix params
        if not self.url.endswith('/'):
            self.url += '/'

        self._skip = list()
    
    def hostinfo(self):
        rurl = urllib.parse.urljoin(self.url,'/api/hostinfo')
        r = requests.get(rurl, timeout=30)
        if r.status_code == 200:
            hinfo = json.loads(r.text)
        else:
            raise Exception('Error code: {} from url {}'.format(r.status_code, rurl))
        
        return r.text
        
    
    @classmethod
    def skip(cls, name):
        print("skip server", name)
        cls._skip.append(name)
    
    def verbose(self):
        err = logging.StreamHandler(sys.stderr)
        self.log.addHandler(err)
        self.log.setLevel(logging.DEBUG)
        self.log.debug('Verbose mode')


    @staticmethod    
    def me():
        return RemoteServer(name = settings.HOSTNAME)
    
    def __str__(self):
        return "RS: "+self.url

    @staticmethod
    def get_machine(ci=None, name=None, url=None):
        if ci is not None:
            return settings.MACHINES[ci]
        
        for ci, machine in settings.MACHINES.items():
            if name:
                if machine['name'] != name:
                    continue
            if url:
                if machine['url'] != url:
                    continue
            return machine
        

    # remoteserver.reset_cache
    def reset_cache(self):
        self.cache = dict()


    # remoteserver.get_ci
    def get_ci(self):            
        if not 'ci' in self.cache:
            rurl = urllib.parse.urljoin(self.url,'/api/hostinfo')
            r = requests.get(rurl, timeout=30)
            if r.status_code == 200:
                hinfo = json.loads(r.text)
            else:
                raise Exception('Error code: {} from url {}'.format(r.status_code, rurl))
            self.cache['ci'] = hinfo['ci']
            
        return self.cache['ci']

    # remoteserver.get_userlist
    def get_userlist(self):
        if not 'userlist' in self.cache:
            rurl = urllib.parse.urljoin(self.url,'/api/admin/cilist')
            r = requests.get(rurl, timeout=30)
            if r.status_code == 200:
                userlist = list( filter(None, r.text.split('\n')) )
            else:
                raise Exception('Error code: {} from url {}'.format(r.status_code, rurl))
            self.cache['userlist'] = userlist
                
        return self.cache['userlist']        

    # remoteserver.get_user
    def get_user(self,email):
        rurl = urllib.parse.urljoin(self.url,'/api/admin/export/{}'.format(email))
        r = requests.get(rurl, timeout=30)
        if r.status_code == 200:
            data = json.loads(r.text)
        else:
            raise Exception('Error code: {} from url {}'.format(r.status_code, rurl))
        return data

    # remoteserver.accept_invite
    def accept_invite(self, email, code):
        rurl = urllib.parse.urljoin(self.url,'/api/admin/accept_invite')
        payload = { 'email': email, 'code': code }
        
        r = requests.post(rurl, data=payload)
        if r.status_code == 200:
            data = json.loads(r.text)
        else:
            raise Exception('Error code: {} from url {} text: {}'.format(r.status_code, rurl, r.text))
        return data
    
    # remoteserver.force_sync
    def force_sync(self, email, server = settings.HOSTNAME):
            
        rurl = urllib.parse.urljoin(self.url,'/api/admin/force_sync')
        payload = { 'email': email, 'server': server }
        
        r = requests.post(rurl, data=payload)
        if r.status_code != 200:
            self.log.error('force_sync exception http status code: {} from url {} text: {}'.format(r.status_code, rurl, r.text))


    def land_url(self, suffix, hostname=None):
        suffix = suffix.lstrip('/')
        if hostname is None:
            hostspec = 'okerr:'+settings.HOSTNAME
        else:
            hostspec = hostname
        
        suffix = urllib.parse.urljoin('/oauth2/login/{}/'.format(hostspec), suffix)
        rurl = urllib.parse.urljoin(self.url,suffix)
        return rurl

    def set_ci(self, ci, email):
        data = { 'ci': ci, 'email': email}
        url = urllib.parse.urljoin(self.url, '/api/setci')
        r = requests.post(url, data)
        if r.status_code != 200:
            print("Error! status: {} url: {}".format(r.status_code, url))
        else:
            print("remote:", r.text)


    def list(self):
        url = urllib.parse.urljoin(self.url, '/api/admin/list')
        r = requests.get(url)
        if r.status_code != 200:
            print("Error! status: {} url: {}".format(r.status_code, url))
        else:
            return json.loads(r.text)
        

    def cilist(self):
        url = urllib.parse.urljoin(self.url, '/api/admin/cilist')
        r = requests.get(url)
        if r.status_code != 200:
            print("Error! status: {} url: {}".format(r.status_code, url))
        else:
            return filter(None, r.text.split('\n'))


    # should we throttle a little bit?
    def tproc_throttle(self):
        if time.time() > self.last_tproc_get + self.tproc_period:
            return False
        return True

    # get task processes name@location is for netprocess
    def get_tproc(self, num=None, headers=None, textid=None, iname=None):

        if num is None:
            num = self.tasks_per_request                

        crlist = list()

        geturl = urllib.parse.urljoin(self.url,'/api/tproc/get')
        reqdata = { 'name': self.client_name, 'location': self.client_location, 'numi': num }

        # self.log.debug('get_tproc (cache: {} / sch: {})'.format(len(self.tcache), len(crlist) ))

        if iname and textid:
            reqdata['iname'] = iname
            reqdata['textid'] = textid            

        self.last_tproc_get = time.time()
        
        try:
            r = requests.post(geturl, data = reqdata, headers = self.headers, timeout=15 )
        except requests.exceptions.RequestException as e:
            self.log.error("get_tproc ({}) from {} error: {}".format(num, self.name, str(e)))
            return []

        self.last_status_code = r.status_code

        if r.status_code != 200:
            msg = "{} code: {}".format(geturl, r.status_code)
            self.log.info(msg)
            return []
            
        for task in json.loads(r.text):
            # remove it from cache (if it's there)
            # fullname = task['name'] + '@' + task['textid']
                        
            cr = check_result.from_request(task, rs_name = self.name)
            cr.msgtags['fetched'] = 1
            crlist.append(cr)

        self.log.debug("troc_get {} tasks from {}".format(len(crlist), self.name))
        return crlist


    def tproc_empty(self):
        if len(self.tproc_results):
            return False
        return True


    def api_director(self, textid=None):
        url = urllib.parse.urljoin(self.url, '/api/director/textid/{}'.format(textid))
        try:
            r = requests.get(url, headers=self.headers, timeout=15)
            if r.status_code == 200:
                return r.text
        except requests.exceptions.RequestException as e:
            self.log.error("{}: api_director {} error: {}".format(self.name, textid, e))
            return None
        except BaseException:
            self.log.error("{}: api_director {} error: {}".format(self.name, textid, e))
            return None


    def api_admin_member(self, email):
        url = urllib.parse.urljoin(self.url, '/api/admin/member/{}'.format(email))
        try:
            r = requests.get(url, headers=self.headers, timeout=15)
            if r.status_code == 200:
                return json.loads(r.text)
        except requests.exceptions.RequestException as e:
            self.log.error("{}: api_director {} error: {}".format(self.name, textid, e))
            return None
        except BaseException:
            self.log.error("{}: api_director {} error: {}".format(self.name, textid, e))
            return None


    def api_admin_chat_id(self, chat_id=None):
        url = urllib.parse.urljoin(self.url, '/api/admin/chat_id/{}'.format(chat_id))
        try:
            r = requests.get(url, headers=self.headers, timeout=15)
            if r.status_code == 200:
                return r.text
        except requests.exceptions.RequestException as e:
            self.log.error(u"{}: api_admin_chatid({}) error: {}".format(self.name, chat_id, e))
            return None

    def api_admin_tglink(self, email=None, tgname=None, chat_id=None):
        url = urllib.parse.urljoin(self.url, '/api/admin/tglink')
        
        try:
            reqdata = dict()

            if tgname:
                reqdata['tgname'] = tgname

            if email:
                reqdata['email'] = email

            if chat_id:
                reqdata['chat_id'] = chat_id
            
            r = requests.post(url, data = reqdata, headers = self.headers, timeout=15 )
            return r.text
        except requests.exceptions.RequestException as e:
            self.log.error(u"{}: api_admin_tglink({}, {}) error: {}".format(self.name, email, chat_id, e))
            return None        

    def api_admin_qsum(self, textid):    
        url = urllib.parse.urljoin(self.url, '/api/admin/qsum/{}'.format(textid))
        self.log.info("GET QSUM FROM {}".format(url))
        
        try:            
            r = requests.get(url, headers = self.headers, timeout=15 )
            if r.status_code == 200:
                return json.loads(r.text)
            return None
        except requests.exceptions.RequestException as e:
            self.log.error(u"{}: api_admin_qsum({}) error: {}".format(self.name, textid, e))
            return None        
    

    def send_tproc_results(self, portion, options = dict()):
                
        seturl = urllib.parse.urljoin(self.url,'/api/tproc/set')

        setdata = dict()
        setdata['name'] = self.client_name
        setdata['location'] = self.client_location
        
        for k, v in options.items():
            setdata[k] = v
        
        res = dict()

        n=0

        for cr in portion:
                
            self.log.info(u'REPORT {} {}'.format(cr.code, cr))
            rd = cr.response()
            textid = rd['textid']            
            if not textid in res:
                res[textid] = list()
            res[textid].append(rd)
            n += 1
    

        setdata['res'] = json.dumps(res, indent=4)
        
        r = requests.post(seturl, setdata, headers = self.headers, timeout=25)
                
        results = dict()    
        if r.status_code == 200:
            tsr = json.loads(r.text)        
                        
            for apply_status in ['applied','not applied']:
                for fullname in tsr[apply_status]:
                    results[fullname] = apply_status                
        else:
            self.log.error("send_tproc {} error code: {}".format(seturl, r.status_code))

        return results

    
    def getsysvar(self,name):
        url = urllib.parse.urljoin(self.url,'/getsysvar/{}'.format(name))
        r = requests.get(url, headers=self.headers, timeout=5)
        if r.status_code == 200:
            return r.text

    def reverse(self, target, kwargs=None):
        return urllib.parse.urljoin(self.url, reverse(target, kwargs=kwargs))

            
    @staticmethod
    # remoteserver.remote_urls
    def UNUSED_remote_urls(self):
        """ return URLs for all remote servers """
        urls = list()
        
        for ci, machine in settings.MACHINES:
            if ci == self.ci:
                continue
            
            urls.append(machine['url'])
        return urls        
    
    def is_net(self):
        if self.url is None or self.url.startswith('http://localhost') or self.url.startswith('https://localhost'):
            # not networked host
            return False        
        return True
        
    @staticmethod
    def all_rs():
        for ci,machine in settings.MACHINES.items():
            rs = RemoteServer(ci = ci)
            if rs.name in RemoteServer._skip:
                continue
            yield rs
    
    def all_other(self):
        for rs in RemoteServer.all_rs():
            if rs.ci != self.ci:
                if rs.name in RemoteServer._skip:
                    continue
                yield rs



        
def myci(name = None):
    if name is None:
        name = settings.HOSTNAME

    rs = RemoteServer( name = name )

    for ci, machine in settings.MACHINES.items():
        if machine['name'] == name:
            return ci



#def ci2rs(ci):
#    return RemoteServer(ci=ci)
    
