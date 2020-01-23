#!/usr/bin/python

import requests
import json
from django.conf import settings

user_agent = 'WWW Security - Okerr.com Dynamic DNS client - 0.1'

class DDNSExc(Exception):
    pass


class DDNSBase(object):

    def __init__(self, hostname=None, domain=None, login=None, secret=None, cache=None): # HDLS
        self.hostname = hostname
        self.domain = domain
        self.login = login
        self.secret = secret
        if domain:
            self.fqdn = hostname + '.' + domain
        else:
            self.fqdn = hostname

        self.headers = dict()
        self.headers['User-Agent'] = user_agent
        self._cache = dict()
        self.cache_updated = False

        if cache:
            self.cache = json.loads(cache)

    def update_cache(self, key, value):
        self._cache[key] = value
        self.cache_updated = True

    def get_cache(self):
        return json.dumps(self._cache)

    def set_record(self, value):
        print("NOT IMPLEMENTED Set record ({}) {} = {}".format(self.method, self.hostname, value))
        pass



class YaPDD(DDNSBase):

    def __init__(self, hostname=None, domain=None, login=None, secret=None, cache=None):
        super(YaPDD, self).__init__(hostname, domain, login, secret, cache)

        # token url: https://pddimp.yandex.ru/api2/admin/get_token
        self.yasrv = 'https://pddimp.yandex.ru/api2/admin/dns/{}'
        self.headers['PddToken'] = secret
        self.ttl = 120 # min: 90


    def check_error(self, r):
        if r.status_code != 200:
            raise DDNSExc('HTTP code: {}: {}'.format(r.status_code, r.text))
        rdata = json.loads(r.text)
        if not 'success' in rdata or not rdata['success']=='ok':
            raise DDNSExc(r.text)

    def get_rid(self, host):
        url = self.yasrv.format('list?domain={}'.format(self.domain))
        r = requests.get(url, headers = self.headers)
        self.check_error(r)

        data = json.loads(r.text)
        # print json.dumps(data, indent=4)
        for r in data['records']:
            if r['subdomain'] == host:
                return r['record_id']

        return None


    def set_record(self, value):
        rid = self.get_rid(self.hostname)
        if rid:
            # change
            return self.change(rid, value)
        else:
            return self.add(self.hostname, value)

    def change(self, rid, content):

        data = {
            'domain': self.domain,
            'record_id': rid,
            'content': content,
            'ttl': self.ttl
        }

        url = self.yasrv.format('edit')
        r = requests.post(
            url,
            data = data,
            headers = self.headers)

        if r.status_code != 200:
            raise DDNSExc("HTTP code {}: {}", r.status_code, r.text)

        rdata = json.loads(r.text)
        if 'success' in rdata and rdata['success'] == 'ok':
            return r.text
        else:
            raise DDNSExc(r.text)

    def add(self, host, content):

        data = {
            'domain': self.domain,
            'subdomain': host,
            'type': 'A',
            'ttl': self.ttl,
            'content': content
        }

        url = self.yasrv.format('add')

        r = requests.post(
            url,
            data = data,
            headers = self.headers)

        if r.status_code != 200:
            raise DDNSExc("HTTP code {}: {}", r.status_code, r.text)

        rdata = json.loads(r.text)
        if 'success' in rdata and rdata['success'] == 'ok':
            return r.text
        else:
            raise DDNSExc(r.text)

class OkerrYaPDD(YaPDD):

    def __init__(self, hostname=None, domain=None, login=None, secret=None, cache=None):
        super(OkerrYaPDD, self).__init__(hostname, domain, login, secret, cache)

        # okerr.com: EV2TIQ744BM3W2MJYY3NXVPUKIHTQKTYDAW4HE5Z42SEZDVKVZJQ
        # dyn1.okerr.com: 5PHGKYF25ASL62MXE4JHTWNRYFOWQWFBZM4SQPNAFROBGGXLNE5A

        self.domain = 'dyn1.okerr.com'
        #self.yasrv = 'https://pddimp.yandex.ru/api2/admin/dns/{}'
        self.headers['PddToken'] = settings.OKERR_PDD_TOKEN
        #self.ttl = 120 # min: 90


class CloudflareDNS(DDNSBase):

    def __init__(self, hostname=None, domain=None, login=None, secret=None, cache=None):
        super(CloudflareDNS, self).__init__(hostname, domain, login, secret, cache)
        self.headers['X-Auth-Key'] = self.secret
        self.headers['X-Auth-Email'] = self.login
        self.ttl = 120 # min cf ttl

    def get_zid(self):

        if 'zid' in self._cache:
            return self._cache['zid']

        r = requests.get('https://api.cloudflare.com/client/v4/zones', headers = self.headers )
        if r.status_code != 200:
            raise DDNSExc('HTTP code: {}: {}'.format(r.status_code, r.text))
        data = json.loads(r.text)

        for z in data['result']:
            if z['name'] == self.domain:
                self.update_cache('zid', z['id'])
                return self._cache['zid']

    def get_records(self):
        zid = self.get_zid()
        r = requests.get('https://api.cloudflare.com/client/v4/zones/{}/dns_records'.format(zid), headers = self.headers )
        if r.status_code != 200:
            raise DDNSExc('HTTP code: {}: {}'.format(r.status_code, r.text))
        data = json.loads(r.text)
        return data

    def get_rid(self):
        if 'rid' in self._cache:
            return self._cache['rid']

        data = self.get_records()
        #print json.dumps(data, indent=4)
        for r in data['result']:
            if r['type'] == 'A' and r['name'] == self.fqdn:
                self.update_cache('rid', r['id'])
                return r['id']


    def check_error(self, r):
        if r.status_code != 200:
            raise DDNSExc('HTTP code: {}: {}'.format(r.status_code, r.text))
        rdata = json.loads(r.text)
        if not 'success' in rdata or not rdata['success']:
            if rdata['errors']:
                raise DDNSExc(str(rdata['errors']))
            raise DDNSExc(r.text)

    # cloudflaredns.create_record
    def create_record(self, value):
        zid = self.get_zid()
        data = {
            'type': 'A',
            'name': self.fqdn,
            'content': value,
            'ttl': self.ttl
        }

        r = requests.post('https://api.cloudflare.com/client/v4/zones/{}/dns_records'.format(zid), json = data, headers = self.headers )

        self.check_error(r)
        return r.text

    def update_record(self, rid, value):
        zid = self.get_zid()
        data = {
            'type': 'A',
            'name': self.fqdn,
            'content': value,
            'ttl': self.ttl
        }

        r = requests.put('https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}'.format(zid, rid), json = data, headers = self.headers )

        self.check_error(r)
        # print "code: {} text: {}".format(r.status_code, r.text)
        return r.text



    def set_record(self, value):
        # print "set record for {} {} ({})".format(self.hostname, self.domain, self.fqdn)
        rid = self.get_rid()
        if rid:
            return self.update_record(rid, value)
        else:
            return self.create_record(value)


class OkerrCloudflareDNS(CloudflareDNS):

    def __init__(self, hostname=None, domain=None, login=None, secret=None, cache=None):
        super(OkerrCloudflareDNS, self).__init__(hostname, domain,
                                                 settings.OKERR_CLOUDFLARE_USER,
                                                 settings.OKERR_CLOUDFLARE_SECRET,
                                                 cache)


class HeNetDNS(DDNSBase):

    def set_record(self, value):
        data = {
            'hostname': self.fqdn,
            'password': self.secret,
            'myip': value
        }

        r = requests.post('https://dyn.dns.he.net/nic/update', data = data)

        if r.status_code != 200:
            raise DDNSExc('HTTP code {}: {}'.format(r.status_code, r.text))

        return r.text
#
# Main unified DynDNS
#

class DynDNS:
    def __init__(self, method=None, hostname=None, domain = None, login = None, secret = None, cache = None):
        self.method = method
        self.hostname = hostname
        self.domain = domain
        self.login = login
        self.secret = secret

        classes = {
            'okerr/yapdd': OkerrYaPDD,
            'yapdd': YaPDD,
            'cloudflare': CloudflareDNS,
            'okerr/cloudflare': OkerrCloudflareDNS,
            'he.net': HeNetDNS,
        }

        try:
            self.service = classes[method](
                hostname = hostname,
                domain = domain,
                login = login,
                secret = secret,
                cache = cache)
        except KeyError:
            raise DDNSExc('Unknown method "{}"'.format(method))

    # dyndns set_record
    def set_record(self, value):
        # print "Set record ({}) {} = {}".format(self.method, self.hostname, value)
        if self.service:
            try:
                return self.service.set_record(value)
            except requests.exceptions.RequestException as e:
                raise DDNSExc("HTTP: {}".format(str(e)))
        else:
            raise DDNSExc('Service not set (method: {})!'.format(self.method))



if __name__ == '__main__':
    pass