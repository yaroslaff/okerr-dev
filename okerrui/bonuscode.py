from django.db import models
from django.utils import timezone
from django.conf import settings

import datetime
import requests
import logging
import hashlib
import string
import re
import random
import pytz

from importlib import import_module

from myutils import chopms,shortdate

log = logging.getLogger('okerr')		

#
# re = u'^testcode:(?P<userid>[a-zA-Z0-9]+)'
# checktype = u'gethttp200:http://localhost/check/user:$userid'
#
#
#


# from okerrui.models import Group, Profile

class BonusCode(models.Model):

    class Meta:
        app_label = 'okerrui'

    # code. just identifier
    name = models.CharField(max_length=200,unique=True) 
        
    # prefix. for lookup
    prefix = models.CharField(max_length=200, default='',unique=False)     
    
    # re
    re = models.CharField(max_length=200,default=None,null=True,unique=True)     
    
    # enabled
    enabled = models.BooleanField(default=True)
    
    # assigns to group for days
    group = models.ForeignKey('Group', on_delete=models.CASCADE)
    time = models.IntegerField(default=30*24*3600, blank=True)

    # If true - no other user can use exactly same code
    personal = models.BooleanField(default=False) 


#    days = models.IntegerField(default=30)
    #
    # if add=True,  expiration = expiration + time 
    # if add=False, expiration = now + time
    add = models.BooleanField(default=False) 
    
    # no activation will happen after this time
    expires = models.DateTimeField(default=timezone.now, blank=True)
    
    # reactivate every N seconds
    reactivation = models.IntegerField(default=None, null=True, blank=True)
    
    
    # if limited: start with left=total, and stops with left=0
    limited = models.BooleanField(default=True)
    total = models.IntegerField(default=100)
    left = models.IntegerField(default=100)
    
    # if repeatable: user can repeat bonus code every repeat_days 
    #   has no meaning for automatical reactivation!
    repeatable = models.BooleanField(default=False)
    repeat_days =  models.IntegerField(default=0)

    verifyurl = models.CharField(max_length=200, blank=True, default='')
    secret = models.CharField(max_length=200, blank=True, default='')


    checktype = models.CharField(max_length=200, blank=True, default='')
    #
    # sha256:MySecret
    # 
    # URL200:http://localhost/check/$1 
    #
    
    

    def __unicode__(self):
        return self.name

    @classmethod
    def get_builtin(cls, name):
        m = import_module('okerrui.models')
        
        codes = {
            'ReleasePromo2019': {
                'group': 'AlcorPromo',
                'time': 86400 * 365,
                'expires': datetime.datetime.strptime("2020-12-31", "%Y-%m-%d")
            }
        }

        if not name in codes:
            return None
        
        
        c = codes[name]
        expiration = c['expires']
        expiration = expiration.replace(tzinfo = pytz.UTC)
        bc = BonusCode()
        bc.group = m.Group.objects.get(name = c['group'])
        bc.name = name
        bc.time = c['time']                
        bc.expires = expiration
        bc.builtin = True
                
        return bc
   

    #
    # find proper code, and check() then apply
    #
    @staticmethod   
    def use(code, profile, apply=True):
       
        # print "use {} / {}".format(code, profile)
        bc = BonusCode.get_builtin(code)
        if bc:
        
            try:
                bc.check_code(code, profile)
            except ValueError as e:
                return str(e)
        
            bc.apply(profile)
            # no need to save, because builtin
            BonusActivation.objects.create(user=profile.user,BonusCode=None, text=code, 
                reactivation = bc.next_reactivation(), expiration = bc.next_expiration())
            return 'Built-in code activated. Good!'
        
        for bc in BonusCode.objects.filter(enabled=True):
            if code.startswith(bc.prefix):
                try:
                    bc.check_code(code, profile)
                    if apply:
                        bc.apply(profile)
                        bc.save() # save, because it could be modified, e.g. left activations changed

                        BonusActivation.objects.create(user=profile.user,BonusCode=bc, text=code, 
                            reactivation = bc.next_reactivation(), expiration = bc.next_expiration())
                        return 'Bonus code activated. Good!'
                    else:
                        return 'Check passed, not activated'
                except ValueError as e:
                    return str(e)        
        return 'No such code'




    
    def next_reactivation(self):
        # find reactivation
        if self.reactivation:
            return timezone.now() + datetime.timedelta(seconds = self.reactivation)
        else:
            return None
        
    """
        returns when BonusActivation should expire and deleted
    """
    def next_expiration(self):
        if self.time:
            return timezone.now() + datetime.timedelta(seconds = self.time)
        else:
            return None


    
    
    def strdump(self):
        out = ''
        out += "Bonus Code: "+self.name
        
        if self.enabled:
            out += " enabled"
        else:
            out += " disabled"
        
        out +='\n'
        
        out +="Regex: {}\n".format(self.re)
        
        td = datetime.timedelta(seconds=self.time)

        if self.add:
            out += "Group {} ADD for {}\n".format(self.group.name,td)
        else:
            out += "Group {} for {}\n".format(self.group.name,td)


        if self.expires:
            if timezone.now() >= self.expires:
                out += "EXPIRED: {}\n".format(self.expires)
            else:
                out += "Expires: {} ({})\n".format(self.expires,chopms(self.expires-timezone.now()))
        else:
            out += "never expires"

        if self.limited:
            out += "Total: {}, Left: {}\n".format(self.total, self.left)
        else:
            out += "Not limited\n"
        if self.repeatable:
            out += "Repeatable every {} days\n".format(self.repeat_days)
        else:
            out += "Not repeatable\n"

        if self.verifyurl:
            out += "verifyurl: {}\n".format(self.verifyurl)
        else:
            out += "no verification\n"

        out += "\nRecent activations:\n"
        for a in self.bonusactivation_set.all().order_by('-activated'):
            out += str(a)+"\n"
        out += '\n'
        return out




    #
    # Apply bonus. No checks
    #

    def apply(self, profile):

        if self.add:
            profile.assign(group=self.group,addtime=datetime.timedelta(seconds=self.time))
        else:
            profile.assign(group=self.group,
                time=self.time)
        if self.limited:
            if self.left>0:
                self.left-=1
                

        
    
   
    def generate(self):
        """Generate random bonuscode which would match this bonuscode"""
        if self.checktype.startswith('sha1:'):
            secret = self.checktype.split(':')[1]
            salt = ''
            for i in xrange(16):
                salt += random.choice(string.digits+'abcdef')
            digest = hashlib.sha1(salt+secret).hexdigest()
            code = self.prefix + salt+ ':' + digest
            return code
        else:
            print("This checktype {} has no generate".format(self.checktype))
        
    
    #
    # check code, if we can apply it or not
    #
    
    def check_code(self,code,profile, reactivation=False):
        

        codedict=dict()
        codedict['_code']=code
        codedict['_email']=profile.user.email

        if self.re:
            m = re.match(self.re,code)
            if not m:
                log.info('incorrect code (regex). user: {} code: {}'.format(profile.user.email, repr(code)))                
                raise ValueError('Code is not correct')
            
            codedict.update(m.groupdict())

        # built-in checks. only user-text
        if hasattr(self, 'builtin'):
            count = BonusActivation.objects.filter(user=profile.user, text=code).count()
            if count>0:
                raise ValueError('This built-in code {} was already used by this user {}'.format(repr(code), profile.user))
        
            
        # check personal
        if self.personal:
            # if any other user used it - we cannot
            count = BonusActivation.objects.filter(BonusCode=self,text=code).exclude(user=profile.user).count()
            if count>0:
                raise ValueError('Personal code already used by other user')

        # checktypes
        if self.checktype.startswith('gethttp200:'):
            try:            
                urltpl = string.Template(self.checktype.split(':',1)[1])
                url = urltpl.substitute(codedict)
        
            except KeyError as e:
                log.info('incorrect code (KeyError: {}). user: {} code: {}'.format(str(e),
                        profile.user.email, repr(code)))                
                raise ValueError('Code is not correct')

            r = requests.get(url)

            if(r.status_code != 200):
                log.info('verification failed. user: {} code: url: {} http code: {}'.format(profile.user.email, 
                        repr(code), url,r.status_code))
                raise ValueError('Bonus vendor verification failed')
            else:
                # GREAT! Passed this verification
                pass

        elif self.checktype.startswith('sha1:'):
            secret = self.checktype.split(':')[1]
            (prefix,salt,digest) = code.split(':')
            
            mydigest = hashlib.sha1(salt+secret).hexdigest() 
            
            if mydigest != digest:
                raise ValueError('Bonus digest verification failed')
            
        if self.expires and timezone.now() >= self.expires:
            raise ValueError("Sorry, bonuscode '{}' is expired".format(code))
            
        if self.limited and self.left<=0:
            raise ValueError("Sorry, such no more activations left")
        
        if not self.enabled:
            raise ValueError("Sorry, disabled")
        
        
        if not reactivation:
            # maybe already used?
            ba = BonusActivation.objects.filter(BonusCode=self,user=profile.user).order_by('-activated').first()
            if ba:
                # already used this code.
                if not self.repeatable:
                    raise ValueError("sorry, you can use this code only once")
                
                timepassed=timezone.now()-ba.activated
                mintime=datetime.timedelta(days=self.repeat_days)
                
                if timepassed<mintime:
                    raise ValueError("sorry, you activated this code {} ago, you can activate it again in {}".format(chopms(timepassed), chopms(mintime-timepassed)))
                
            if self.verifyurl:
                log.info('bonuscode \'{}\' verify \'{}\''\
                    .format(self.name,self.verifyurl))
                payload = {'email': profile.user.username, 'bonuscode': self.name}
                r = requests.post(self.verifyurl,data=payload)
                log.info('bonus verify status_code: {} content: {}'.format(r.status_code,r.content))
                if r.status_code == 200 and r.content=='1':
                    log.info('bonuscode verification ok')
                else:
                    log.info('bonuscode verification fails (s:{} c:{})'.format(r.status_code, r.content))
                    raise ValueError('bonuscode verification failed')

        # self.apply(profile)
        # return "Bonus code {name} applied!".format(name=self.name)
        return True # always True if here. if not true - exception
        

#
# BonusActivation use cases
# 1. Prevent multiple use of bonuscode (if bonuscode.repeatable==True, it cannot be reused for same user. Only used one time)
# 2. Keep automatical reactivation of bonus-vendor codes. (e.g. User will have membership only when he is customer of hosting company)
#

class BonusActivation(models.Model):

    class Meta:
        app_label = 'okerrui'

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    BonusCode = models.ForeignKey(BonusCode, on_delete=models.CASCADE, null=True)
    text = models.CharField(max_length=200,null=True,default=None)  # bonus code itself
    activated = models.DateTimeField(auto_now_add=True, blank=True)
    reactivation = models.DateTimeField(null=True, default=None)     # check and apply at that time
    expiration = models.DateTimeField(null=True, default=None)       # delete at that time. (none: keep forever)


    @staticmethod           
    def cron():
        
        #
        # extend (reapply)
        # 
        # delete old
        #
        now = timezone.now()
    
        for ba in BonusActivation.objects.filter(reactivation__isnull=False, reactivation__lt=now):
            ba.reapply()
            
        #
        # delete expired
        #
        for ba in BonusActivation.objects.filter(expiration__isnull=False, expiration__lt=now):
            log.info("{} expire".format(ba))
            ba.expire()
        

    def expire(self):
        """Delete self or disable"""            
        # print "{} expire self".format(self)
        if self.BonusCode and self.BonusCode.repeatable:
            # just delete. 
            self.delete()
        else:
            # not repeatable. disable reactivation 
            self.expiration = None
            self.reactivation = None
            self.save()
                        

    def reapply(self):
        log.info("{} reapply".format(self))
        try:
            self.BonusCode.check_code(self.text, self.user.profile, reactivation=True)
            log.info("check ok")
            self.BonusCode.apply(self.user.profile)
            self.expiration = self.BonusCode.next_expiration()
                
        except ValueError as e:
            # failed. chedule next verification, but do not change expiration
            log.info("check failed: {}".format(str(e)))

        # reactivate anyway
        self.reactivation = self.BonusCode.next_reactivation()
        
        self.save()




    def __unicode__(self):
        return "{} {} {} ({}) reactivation: {} expiration: {}".format(
                shortdate(self.activated),
                self.user.username,
                self.BonusCode,
                repr(self.text),
                self.reactivation,
                self.expiration)

