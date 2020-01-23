import redis
import json
import time
import inspect
import logging
import os

from okerrui.remotecheck import check_result

class NoCR(Exception):
    pass

class CRCache():
    
    # Exceptions
    NoCR = type(NoCR())

    def __init__(self, connection = None):
        if connection:
            self.r = connection
        else:
            self.r = redis.Redis(decode_responses=True)
                
        self.log = logging.getLogger('okerr')
    
    
    def set_redis(r):
        self.r = r
    
    # store/update checkresult
    def store(self, cr, recname, expire=7200, schedule=False, target=None, map_prefix=None):
            
        d = cr.serialize()
        fullname = d['name'] + '@' + d['textid']

        pipe = self.r.pipeline()
        
        
        for k, v in d.items():

            if v is None:
                pipe.hdel(recname, k)

            elif isinstance(v, dict) or isinstance(v, list) or isinstance(v, bool):
                pipe.hset(recname, k, json.dumps(v))

            # elif isinstance(v, str) or isinstance(v, unicode) or isinstance(v, int) or isinstance(v, float):
            elif isinstance(v, str) or isinstance(v, int) or isinstance(v, float):
                pipe.hset(recname, k, v)

            else:
                print("{}: unknown type {} ({})".format(k,type(v),repr(v)))

        if target:
            if cr.scheduled and schedule:
                # store in sorted set
                # print "store: schedule", fullname, inspect.stack()[1][3]
                # self.log.info("schedule {} to {}".format(fullname, cr.scheduled))
                mapping = {
                    recname: cr.scheduled
                }
                pipe.zadd(target,mapping)
                self.stage(fullname,"scheduled",pipe=pipe)                                    
            else:
                # store, but not schedule, store in set
                pipe.sadd(target, recname)
    
        if map_prefix:
            map_name = map_prefix + cr.fullname
            pipe.set(map_name, recname)
            if expire:
                pipe.expire(map_name, expire)
    
        if expire:
            pipe.expire(recname, expire)
    
        pipe.execute()
        return recname
        
    def still_actual(self, cr):
        # get actual fetch_id
        # cfid = cr_cache.r.hget('fids', cr.fullname)
        return cr.fetch_id == self.r.hget('fids', cr.fullname)
            
    # record processing stage for indicator    
    def stage(self, name, s, pipe=None):
        
        if pipe:
            r = pipe
        else:
            r = self.r
        
        if s:
            r.hset("stage",name,s)
        else:
            r.hdel("stage",name)
            
    def load(self, recname):
        # print "Load indicator", fullname
        d = self.r.hgetall(recname)

        if not d:
            raise NoCR(u'no such indicator {}'.format(recname)) 
        
        cr = check_result()
        for k,v in d.items():
            curval = getattr(cr,k,None)
            
            if isinstance(curval, list) or isinstance(curval, dict) or isinstance(curval, bool):
                setattr(cr, k, json.loads(v))
            elif isinstance(curval, int):
                setattr(cr, k, int(v))            
            elif isinstance(curval, float):
                setattr(cr, k, float(v))            
            #elif isinstance(curval, unicode):
            #    setattr(cr, k, unicode(v,'utf-8'))
            else:
                setattr(cr, k, v)


        # fix name / textid to unicode
        for un in ['name', 'textid','fullname']:
            v = getattr(cr, un, None)
            if isinstance(v, str):
                setattr(cr, un, v)
                # setattr(cr, un, unicode(v,'utf8'))

        if not cr.name or not cr.textid:
            self.log.error('!!! {} {}{}: empty name {} or textid {}'.format(os.getpid(), prefix, fullname, repr(cr.name), repr(cr.textid))) 
            self.log.error('{}'.format(repr(d)))
                
        # print "Loaded",cr.fullname, cr.period
        return cr

    def UNUSED_update(self, fullname, name, value):
        # print "update {} {} = {}".format(fullname, name,repr(value))
        self.r.hset('indicator:'+fullname,  name, value)
        # print "CHECK:",self.r.hget('indicator:'+fullname,  name)

                
    def reschedule(self, fullname=None, cr=None):
        self.log.debug(u"crcache reschedule {}".format(fullname))
        cr = self.load(fullname)
        cr.reborn()
        cr.msgtags["cached"] = 1
        self.store(cr)

                
    def reschedule_or_forget(self, fullname, prefix='send:'):
        # print "reschedule/forget",fullname
        cr = self.load(fullname, prefix=prefix)
        if cr.worthcache():            
            cr.reborn()
            cr.msgtags["cached"] = 1
            self.store(cr, prefix='sch:')
        else:
            self.forget(fullname)
        
    def forget(self, fullname):
        self.log.debug(u"crcache forget {}".format(fullname))        
        pipe = self.r.pipeline()
        
        # remove from scheduled
        pipe.zrem("sch", fullname)
        pipe.delete("indicator:" + fullname)
        pipe.delete("send:" + fullname)
        pipe.srem('locked', fullname)        
        self.stage(fullname,"forgotten")        
        pipe.execute()
        
    def get_scheduled(self, num=None, key='scheduled', delete=True):
        for i in self.r.zrangebyscore(key,min='-inf', max=time.time(), start=0, num=num):
            # self.log.debug('get_scheduled: {}'.format(i))
            self.r.zrem(key, i)            
            cr = self.load(i)
            if delete:
                self.r.delete(i)
            yield cr

    def num_scheduled(self, now=None):
        if now is None:
            now = time.time()
        
        return self.r.zcount('sch', '-inf', now)

    def num_locked(self):
        return self.r.scard('locked')

    # pass commands            
    def zadd(self, skey, name, score):        
        return self.r.zadd(skey, name, score)

    def sadd(self, skey, name):        
        return self.r.sadd(skey, name)

    def srem(self, skey, name):        
        return self.r.srem(skey, name)

    def scard(self, skey):        
        return self.r.scard(skey)


    def smembers(self, name):            
        return self.r.smembers(name)

    def sismember(self, key, name):            
        return self.r.sismember(key, name)

    def zrank(self, key, name):            
        return self.r.zrank(key, name)
            
    def srem(self, skey, name):
        return self.r.srem(skey, name)
        
        
