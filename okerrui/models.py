# coding=utf-8

from django.db import models, IntegrityError, connection, transaction
from django.db.models import Q, Sum, Max, Min
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.exceptions import ValidationError, ObjectDoesNotExist, PermissionDenied
from django.conf import settings
from django.template.loader import get_template
from django.template import Context
from django.core.mail import EmailMultiAlternatives
from django.core.cache import caches
from django.utils.translation import ugettext_lazy as _, pgettext

from netaddr import IPNetwork, IPAddress, AddrFormatError

import datetime
import re
import time
import random
import types
import os
import sys
import string
import inspect
import traceback
import logging
import requests
import json
import hmac
import hashlib
import zlib
import base64
import shlex
import fnmatch
import subprocess
import select
import operator
import collections
import redis

import OpenSSL
import ssl
import socket

import evalidate

# from okerrui.bonuscode import BonusCode
# from transaction.models import TransactionEngine, Transaction, TransactionError, myci
# from transaction.models import myci
from okerrui.cluster import RemoteServer, myci  # ci2rs

from okerrui.impex import Impex

# import okerrui.datasync

from myutils import (
    shortdate,
    shorttd,
    chopms,
    mybacktrace,
    strdiff,
    # forceunicode,
    # forcestr,
    prefixes,
    str2dt,
    shortstr,
    dt2unixtime,
    unixtime2dt,
    send_email,
    timesuffix2sec,
    dhms,
    get_redis
)

from okerrui.exceptions import OkerrError

from timestr import TimeStr
from dyndns import DynDNS, DDNSExc
from verification_code import VerificationCode

from tree import Tree

log = logging.getLogger('okerr')


# def myci():
#    return okerrui.impex.myci()


# Create your models here.
def set_rid(o):
    if o.rid:
        return False

    mname = o.__class__.__name__

    if not o.pk:
        log.info("force save in set_rid for {}".format(mname))
        o.save()

    if o.id is None:
        raise ValueError('set_rid for {} with id {}'.format(mname, o.id))
    o.rid = o.__class__.__name__ + ':' + settings.HOSTNAME + ':' + str(o.id)
    # log.info("new rid: {} (not saved yet)".format(o.rid))
    return True


# universal tsave
def uni_tsave(self):
    if set_rid(self):
        # log.info('set RID for {}'.format(self.rid))
        self.save()
    self.touch()
    self.save()


def safe_getattr(o, path, msg=None):
    pa = path.split('.')

    oo = o
    try:
        for p in pa:
            oo = getattr(oo, p)
    except (ObjectDoesNotExist, AttributeError):
        if msg is not None:
            return msg
        return "<NO {}>".format(path)
    return oo


def dhms_short(sec, sep=" ", num=2):
    out = ""
    nn = 0
    t = {'d': 86400, 'h': 3600, 'm': 60, 's': 1}
    for k in sorted(t, key=t.__getitem__, reverse=True):
        if sec > t[k]:
            if nn == num:
                break
            nn += 1
            n = int(sec / t[k])
            sec -= n * t[k]
            out += "%d%s%s" % (n, k, sep)
    return out.rstrip()


class TransModel(models.Model):
    deleted_at = models.DateTimeField(default=None, null=True)
    trans_last_update = models.DateTimeField(default=None, null=True)  # updated at master
    trans_last_sync = models.DateTimeField(default=None, null=True)  # updated at slave
    rid = models.CharField(max_length=100, default='', db_index=True)
    ci = models.IntegerField(db_index=True, default=0)

    class Meta:
        abstract = True

    def set_delete(self):
        self.deleted_at = timezone.now()

    def set_rid(self):

        if self.rid:
            return False

        mname = self.__class__.__name__

        if not self.pk:
            log.info("force save in set_rid for {}".format(mname))
            self.save()

        if self.id is None:
            raise ValueError('set_rid for {} with id {}'.format(mname, self.id))
        self.rid = self.__class__.__name__ + ':' + settings.HOSTNAME + ':' + str(self.id)
        return True

    def title(self):
        return '{} #{} {}:{} {} {} {}'.format(
            self.__class__.__name__, self.id,
            "ci(my)".format(self.ci) if self.ci == myci() else "ci(other)",
            self.ci,
            self.rid,
            self,
            '[DELETED: {}]'.format(self.deleted_at) if self.deleted_at else ''
        )

    def dtage(self, dt):
        if dt is None:
            return None
        age = timezone.now() - dt
        return dhms_short(age.total_seconds())

    # transmodel.touch
    def fulldump(self):
        print(self.title())
        print("trans_last_update: {} ({})".format(self.trans_last_update, self.dtage(self.trans_last_update)))
        print("trans_last_sync: {} ({})".format(self.trans_last_sync, self.dtage(self.trans_last_sync)))

    # transmodel.touch
    def touch(self):

        self.set_rid()

        self.mtime = timezone.now()
        self.trans_last_update = timezone.now()
        # te = TransactionEngine()
        # te.update_instance(self)

    # transmodel.postload
    def transaction_postload(self, d):
        self.trans_last_sync = timezone.now()


class Project(TransModel):
    name = models.CharField(max_length=200)
    created = models.DateTimeField(auto_now_add=True)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    # defpolicy = models.ForeignKey('Policy', related_name='+', null=True)
    lastcron = None
    jkeys = models.TextField(default='{}')
    mtime = models.DateTimeField(auto_now=True)
    limited = models.BooleanField(default=False)
    partner_access = models.BooleanField(default=False)

    # project.set_ci
    def set_ci(self, ci, force=False):
        """ set cluster index """
        if self.ci == ci and not force:
            return

        print("Project {} set to ci {}".format(self, ci))
        self.ci = ci

        # speed-up!
        self.policy_set.update(ci=ci)
        self.indicator_set.update(ci=ci)

        # for p in self.policy_set.all():
        #    p.set_ci(ci,force)
        #    p.save()

        # for i in self.indicator_set.all():
        #    i.set_ci(ci,force)
        #    i.tsave()

    # project.reanimate
    def reanimate(self):
        for i in self.indicator_set.all():
            i.reanimate()
            i.save()

    def recheck(self):
        l = list()
        cmlist = CheckMethod.objects.exclude(codename__in=CheckMethod.passive_list)

        for i in self.indicator_set.filter(_status='ERR', silent=False, disabled=False,
                                           maintenance__isnull=True, cm__in=cmlist):
            i.retest()
            i.save()
            l.append(i.name)

        return l

    # project.touch
    def touch(self, touchall=False):
        set_rid(self)
        self.mtime = timezone.now()

        # te = TransactionEngine()
        # te.update_instance(self)

        if touchall:
            self.save()
            self.owner.profile.touch(touchall)

    # project.tsave()
    def tsave(self):
        uni_tsave(self)

    # project.create
    @staticmethod
    def create(name, owner, partner_access=False, textid=None):

        log.info("user: {} ci: {} create project: {}".format(owner, owner.profile.ci, name))

        project = Project.objects.create(name=name, owner=owner, ci=owner.profile.ci, partner_access=partner_access)
        set_rid(project)
        project.save()  # cannot touch here! defpolicy not ready

        tm = ProjectMember(project=project, email=owner.email, iadmin=True, tadmin=True)
        set_rid(tm)
        tm.tsave()

        # create default policy
        p = Policy.objects.filter(project=project, name="Default").first()
        if not p:
            p = Policy.objects.create(
                project=project,
                name="Default",
                period=3600,
                patience=1200,
                autocreate=True,
                reduction='0',
                retry_schedule="",
                recovery_retry_schedule="",
                secret="")

            p.tsave()
            log.info('created policy: {} rid: {} for project {}'.format(p.name, p.rid, project.name))

            # world access
            subnet = PolicySubnet(policy=p, subnet='0.0.0.0/0',
                                  remark='IPv4 world access (default)')
            subnet.save()

            subnet = PolicySubnet(policy=p, subnet='::/0',
                                  remark='IPv6 world access (default)')
            subnet.save()

        # project.defpolicy=p

        # create daily policy
        p = Policy.objects.filter(project=project, name="Daily").first()
        if not p:
            try:
                p = Policy.objects.create(
                    project=project,
                    name="Daily",
                    period=86400,
                    patience=7200,
                    autocreate=True,
                    retry_schedule="",
                    recovery_retry_schedule="",
                    secret="")

                p.tsave()  # tsave for RID and transactions
                log.info('created policy: {} rid: {} for project {}'.format(p.name, p.rid, project.name))

                # world access
                subnet = PolicySubnet(policy=p, subnet='0.0.0.0/0',
                                      remark='IPv4 world access (default)')
                subnet.save()

                subnet = PolicySubnet(policy=p, subnet='::/0',
                                      remark='IPv6 world access (default)')
                subnet.save()

            except BaseException as e:
                print("Exception", e)
                print("at ", sys._getframe().f_code.co_name)

        if textid:
            if ProjectTextID.objects.filter(textid=textid).count() == 0:
                print("set textid:", textid)
                t1 = ProjectTextID(project=project, textid=textid)
                t1.save()
            else:
                print("ALREADY exists project with textid", textid)
                project.mk1textid()
        else:
            project.mk1textid()

        # create keys
        # keypasswd = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(10))
        keypasswd = ''

        # read template JKEYS_TPL
        project.jkeys = settings.JKEYS_TPL
        # project.save()

        project.addkey('@access')
        project.addkey('client', keypasswd, '@access')
        project.tsave()

    # project.cron
    @classmethod
    def cron(cls):
        pass

    #
    # project.get_indicator
    #
    # return indicator or throw error
    #
    # iid is 'autodetect'. (id or name)
    #
    # if deleted=False (like default) - look only for live indicator, with deleted_at is NULL
    #
    #

    def get_indicator(self, iid=None, id=None, name=None, deleted=False):
        q = dict()

        q['project'] = self
        # just one: iid, id or name must be used
        if iid is not None:
            try:
                iid = int(iid)
            except ValueError:
                # this is name
                q['name'] = iid
            else:
                # this is number
                q['id'] = iid
        elif id is not None:
            q['id'] = int(id)
        elif name is not None:
            q['name'] = name

        if deleted is not None:
            q['deleted_at__isnull'] = not deleted

        return Indicator.objects.get(**q)

    # project.get_defpolicy()
    def get_defpolicy(self):
        dp = self.policy_set.filter(name="Default").first()
        if dp:
            return dp
        dp = self.policy_set.first()
        return dp

    # project.geti
    # OBSOLETE
    # maybe can crash if there is deleted indicator with same name
    def geti(self, idname):
        try:
            iid = int(idname)
        except ValueError:
            # this is name
            return Indicator.objects.get(project=self, name=idname)
        else:
            # this is number
            return Indicator.objects.get(project=self, pk=iid)

    # project.addmember
    def add_member(self, user):
        pm, created = ProjectMember.objects.get_or_create(project=self, email=user.email)

    # project.remove_member
    def remove_member(self, user):
        pm = ProjectMember.objects.filter(project=self, email=user.email).first()
        pm.delete()

    # project.fix
    def fix(self, verbose):
        # check for duplicate indicators
        lasti = None
        printed = False
        for i in self.indicator_set.filter(deleted_at__isnull=True).order_by('name'):
            if lasti and i.name == lasti.name:
                # duplicate!
                # print first
                if not printed:
                    print("{} {}@{}".format(lasti.id, lasti.name, self.get_textid()))
                    printed = True
                print("{} {}@{}".format(i.id, i.name, self.get_textid()))
            else:
                printed = False
            lasti = i

    # project.keytree
    def keytree(self):
        t = Tree();

        # print "load keys: {}".format(self.jkeys)

        t.loadjson(self.jkeys)
        return t

    # project.addkey
    def addkey(self, name=None, value=None, parentpath=''):

        # print "## project.addkey name={} value={} parentpath={}".format(name, value, parentpath)
        tree = self.keytree()
        # tree.dump()
        # print "project.addkey call tree.add for value={}".format(value)
        tree.add(parentpath, name, value)
        self.jkeys = tree.getjson()
        self.save()
        return

    # project.delkey
    def delkey(self, keyname):
        t = self.keytree()
        t.delete(keyname)
        self.jkeys = t.getjson()
        self.save()

    def getkey_raw(self, path):
        tree = Tree()
        d = json.loads(self.jkeys)
        tree.d = d
        k = tree.key(path, noat=False, include=False)
        return k

    # project.getkey
    def getkey(self, path):
        # print "p#{} {} getkey '{}'".format(self.id, self.name, path)
        tree = Tree()
        d = json.loads(self.jkeys)
        tree.d = d
        # print "project.getkey",path
        k = tree.getkey(path)
        # print "project.getkey: got it, k:",k
        return k

    # project.indicators_deep
    def indicators_deep(self):
        # used in templates
        # started=time.time()
        qs = self.indicator_set.filter(deleted_at__isnull=True).select_related('cm', 'project',
                                                                               'policy').prefetch_related(
            'cm__checkarg_set', 'iarg_set', 'iarg_set__user')
        # print "_deep: {} sec".format(time.time()-started)
        return qs

    # project.req_attentions
    def req_attention(self):
        # started=time.time()
        for i in self.indicator_set.filter(disabled=False):
            if 'ATTENTION' in i.tags():
                return True
        return False

    # project.minperiod
    def minperiod(self):
        return self.owner.profile.getarg('minperiod')

    # project.get_na_indicatos
    # return number of non-disabled indicators
    def get_na_indicators(self):
        na = self.indicator_set.filter(disabled=False).count()
        return na

    # project.active
    def active(self):
        # not implemented. stub
        return True

    # project.dump
    def dump(self):

        members = list()
        for pm in self.projectmember_set.all():
            members.append(pm.email)

        tidlist = list()
        for tid in self.projecttextid_set.all():
            tidlist.append(tid.textid)

        # print "Project #{}: {} {}".format(self.id, self.name, "[DELETED: {}]".format(self.deleted_at) if self.deleted_at else "" )
        print(self.title())
        print("Owner:", self.owner)
        print("Members({}): {}".format(len(members), ' '.join(members)))
        print("Indicators:", self.indicator_set.count())
        print("TextID:", ' '.join(tidlist))
        print("Partner access:", self.partner_access)
        if self.limited:
            print("limited")
        else:
            print("not limited")

        for pi in self.projectinvite_set.all():
            print("  invite:", pi)
        print();

    # project.log
    def log(self, message, typecode='project'):
        LogRecord(project=self,
                  indicator=None,
                  typecode=LogRecord.get_typecode(typecode),
                  message=message.replace('\n', ' ')).save()

    # project.stats
    def stats(self):
        stats = {'ni': 0, 'enabled': 0}
        for i in self.indicator_set.all():
            stats['ni'] = stats['ni'] + 1
            if i.enabled():
                stats['enabled'] = stats['enabled'] + 1
        return stats

    # project.get_by_textid
    @staticmethod
    def get_by_textid(textid):
        try:
            project = Project.objects.get(projecttextid__textid=textid)
        except ObjectDoesNotExist:
            return None
        return project

    def check_api_key(self, key):
        return self.projectaccesskey_set.filter(key=key).count() > 0

    def check_user_access(self, user, role=None):
        """
        raise PermissionDenied if user has not proper role in project
        :param user:
        :param role:
        :return:
        """
        role = role or 'member'

        if role == 'member':
            if self.member(user):
                return True

        if role == 'iadmin':
            if self.iadmin(user):
                return True

        if role == 'tadmin':
            if self.tadmin(user):
                return True

        raise PermissionDenied

    # project.get_textid
    def get_textid(self):
        tid = self.projecttextid_set.first()
        if tid is None:
            return None
        return tid.textid

    # project.get_textids get LIST of textid
    def get_textids(self):
        tidlist = list()
        for tid in self.projecttextid_set.all():
            tidlist.append(tid.textid)
        return tidlist

    # project.member
    def member(self, user):
        if ProjectMember.objects.filter(email=user.email, project=self).count() > 0:
            return True
        return False

    def iadmin(self, user):
        if user == self.owner:
            # owned always admin
            return True
        # look for ProjectMember
        if ProjectMember.objects.filter(email=user.email, project=self, iadmin=True).count() > 0:
            return True
        return False

    # project.tadmin
    # strange name historical reason: tadmin = Team Admin.
    def tadmin(self, user):
        if user == self.owner:
            # owned always admin
            return True
        # look for ProjectMember
        if ProjectMember.objects.filter(email=user.email, project=self, tadmin=True).count() > 0:
            return True
        return False

    # project.members
    def members(self):
        out = list()
        User = get_user_model()

        for pm in self.projectmember_set.all():
            try:
                user = User.objects.get(email=pm.email)
                out.append(user)
            except User.DoesNotExist:
                pass

        return out

    def nmembers(self):
        c = ProjectMember.objects.filter(project=self).count()
        return c

    def updatemin(self):
        d = None
        for i in self.indicator_set.all():
            if d is None:
                d = i.updated
            elif d > i.updated:
                d = i.updated
        return d

    def updatemax(self):
        d = None
        for i in self.indicator_set.all():
            if d is None:
                d = i.updated
            elif d < i.updated:
                d = i.updated
        return d

    # project.metatags
    def metatags(self):
        taglist = ['OK', 'ERR', 'silent', 'disabled', 'maintenance', 'pending', 'passive', 'active']  # special tags
        codenames = CheckMethod.codenames()
        taglist.extend(codenames)
        return taglist

    # project.tags
    def UNUSED_tags(self):
        taglist = ['OK', 'ERR', 'silent', 'disabled', 'maintenance', 'pending', 'passive', 'active']  # special tags
        taglist = []
        # codenames=CheckMethod.codenames()
        # print codenames
        # taglist.extend(codenames)

        for tag in self.indicatortag_set.all():
            if not tag.name in taglist:
                taglist.append(tag.name)
        return taglist

    # project.predelete
    def predelete(self):
        # prepare for deletion
        self.indicator_set.all().delete()
        self.projectmember_set.all().delete()
        self.projecttextid_set.all().delete()
        self.policy_set.all().delete()

    # project.getntextid
    @staticmethod
    def gentextid():
        while True:
            l = 10
            # return "xxx"
            textid = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(l))
            # check this textid
            if ProjectTextID.objects.filter(textid=textid).first() is None:
                return textid

    # project.addtextid
    def addtextid(self, textid):
        mintextidlen = self.owner.profile.getarg('mintextidlen')

        if mintextidlen is None:
            mintextidlen = 6  # default

        if len(textid) < mintextidlen:
            raise ValueError("textid '{}' is too short. mintextid: {}".format(textid, mintextidlen))

        if not re.match('^[a-z0-9\-\.]+$', textid):
            raise ValueError("Incorrect characters in textid '{}'".format(textid))

        if self.projecttextid_set.count() >= 3:
            raise ValueError("Project already has 3 or more textid")

        # try:
        ProjectTextID.objects.create(project=self, textid=textid)
        # except IntegrityError as e:
        #    raise ValueError
        # else:
        #    return True

    #
    # project.can_accept
    #
    # returns tuple (bool,err)
    # bool for can (true) or not (false)
    # err is error message (if bool is false)
    #
    def can_accept(self, user):
        # check if user is already in this group
        if ProjectMember.objects.filter(project=self, email=user.email).count() > 0:
            return (False, "User {u} already member of project {project}".format(u=user.username, project=self.name))

        tsize = self.owner.profile.getarg('teamsize')

        if self.nmembers() >= tsize:
            return (False, "Project already has {}/{} users".format(self.nmembers(), tsize))

        # check if group is active
        # check if owner has permissions, e.g. group is not too big
        return (True, "")

    # project.mk1textid
    def mk1textid(self, *args, **kwargs):
        # print "save profile {} with textid '{}'".format(self.user,self.textid)
        fails = 0
        maxtry = 3

        ctextid = ProjectTextID.objects.filter(project=self).count()

        if ctextid == 0:

            success = False
            failures = 0

            while not success:
                try:
                    textid = Project.gentextid()
                    ProjectTextID.objects.create(project=self, textid=textid)
                except IntegrityError as e:
                    print("warn ", e)
                    failures += 1
                    if failures > 5:  # or some other arbitrary cutoff point at which things are clearly wrong
                        raise
                else:
                    success = True

    # project.stringstat
    def stringstat(self):
        nok = 0
        nerr = 0
        natt = 0
        ndis = 0
        nsilent = 0
        nmain = 0
        ntotal = 0

        for i in self.indicator_set.all():
            ntotal += 1
            tags = i.tags()

            if i.disabled:
                ndis += 1
            elif i.maintenance:
                nmain += 1
            elif i.silent:
                nsilent += 1
            elif i.status == "ERR":
                nerr += 1
            elif i.status == "OK":
                nok += 1
            else:
                print("ERR: unknown status {} for {}".format(i.status, i))

            if 'ATTENTION' in tags:
                natt += 1

        stat = "total: {ntotal}, OK: {nok}, ATT: {natt}, ERR: {nerr}, silent: {nsilent} maintenance: {nmain}, disabled: {ndis}" \
            .format(ntotal=ntotal, nok=nok, natt=natt, nerr=nerr, nmain=nmain, ndis=ndis, nsilent=nsilent)

        return stat

    # project.sendsummary
    def sendsummary(self, remark=None):

        log.info("sendsummary for project: {} remark: {}" \
                 .format(self.name, remark, 'utf-8'))

        from_email = settings.FROM
        plaintext = get_template('summary-project-email.txt')
        htmly = get_template('summary-project-email.html')

        for user in self.members():

            p = user.profile
            if remark:
                subject = 'okerr summary ({})'.format(remark)
            else:
                subject = 'okerr summary'
            indicators = self.indicator_set.all()

            d = {
                'username': user.email,
                'indicators': indicators,
                'remark': remark,
                'project': self,
                'siteurl': settings.SITEURL.strip('/'),
                'hostname': settings.HOSTNAME,
                'MYMAIL_FOOTER': settings.MYMAIL_FOOTER
            }

            text_content = plaintext.render(d)
            html_content = htmly.render(d)

            send_email(user.email, subject=subject, html=html_content, what="project_summary")

            # msg = EmailMultiAlternatives(subject, text_content, from_email, [user.email])
            # msg.attach_alternative(text_content, "text/plain")
            # msg.attach_alternative(html_content, "text/html")

            # msg.mixed_subtype = 'related'

            # flags=[]
            # for i in indicators:
            #    for f in i.flags():
            #        if not f in flags:
            #            flags.append(f)

            # for f in flags:
            #    fname = os.path.join(os.path.dirname(__file__),"static/iflags", f+'.png')
            #    fp = open(fname, 'rb')
            #    msg_img = MIMEImage(fp.read())
            #    fp.close()
            #    msg_img.add_header('Content-ID', '<{}>'.format(f+'.png'))
            #    msg.attach(msg_img)

            # msg.send()

            p.lastsummary = timezone.now()
            p.save()

    def __str__(self):
        return self.name

    # project.backup
    def backup(self):
        backup = {}
        backup['name'] = self.name

        backup['policies'] = []
        for p in self.policy_set.all():
            backup['policies'].append(p.backup())

        backup['indicators'] = []
        for i in self.indicator_set.all():
            backup['indicators'].append(i.backup())

        # print keys:

        backup['keys'] = json.loads(self.jkeys)

        return backup

    # project.rawdatastruct
    def rawdatastruct(self):

        s = dict()
        s['pid'] = self.id
        s['name'] = self.name
        s['indicators'] = dict()
        s['policies'] = dict()
        s['now'] = dt2unixtime(datetime.datetime.now())

        for i in self.indicator_set.select_related('policy').all():
            if i.deleted_at:
                continue

            iname = re.sub('\.', '_', i.name)
            s['indicators'][i.name] = i.rawdatastruct()

        for p in self.policy_set.all():
            s['policies'][p.id] = p.rawdatastruct()

        return s

    # project.datastruct
    def datastruct(self):
        time = timezone.now()

        def incvar(d, name, status):
            # no disabled here.

            # create dummy
            for s in ['OK', 'ERR', 'MAINTENANCE', 'SILENT']:
                sname = ':'.join([s, name])
                if not sname in d:
                    d[sname] = 0
            sname = ':'.join([status, name])
            d[sname] += 1

        s = {}
        s['s'] = {}
        s['i'] = {}
        s['_pid'] = self.id
        s['_pname'] = self.name
        s['hhmm'] = time.hour * 100 + time.minute
        s['day'] = time.day
        s['month'] = time.month
        s['year'] = time.year
        s['weekday'] = time.weekday()
        s['prefix'] = {}
        s['tags'] = {}
        s['age'] = {}

        s['age']['errage'] = 0
        s['age']['uerrage'] = 0

        for i in self.indicator_set.all():
            iname = re.sub('\.', '_', i.name)

            # disabled almost deleted
            if i.disabled or i.deleted_at:
                continue

            ds = i.datastruct()
            s['i'][iname] = ds

            if s['i'][iname]['status'] == 'OK':
                s['s'][iname] = True
            else:
                s['s'][iname] = False

            for p in prefixes(iname):
                incvar(s['prefix'], p, i.okerrm())

            for tag in i.tags():
                incvar(s['tags'], tag, i.okerrm())

                # age

                for agesubtag in ['errage', 'uerrage']:
                    agetag = tag + ':' + agesubtag
                    if not agetag in s['age']:
                        s['age'][agetag] = 0

                    if ds[agesubtag] > s['age'][agetag]:
                        s['age'][agetag] = ds[agesubtag]

        return s

    # project.restore
    def restore(self, s):
        iexist = 0
        irestored = 0

        for p in s['policies']:
            Policy.restore(self, p)

        for istr in s['indicators']:
            i = Indicator.restore(self, istr)
            if i:
                irestored += 1
            else:
                iexist += 1

        # json.loads(self.jkeys)
        self.jkeys = json.dumps(s['keys'])
        self.save()

    # project.getitree
    def getitree(self, prefix=None, tags=[]):
        it = IndicatorTree()
        it.settags(tags)
        for i in self.indicator_set.all():
            it.add(i)
        # print "IT DUMP {}".format(self.name)
        # it.dump()
        # print "---"
        # it.simulate()
        return it

    # project.transaction_postdump
    def transaction_postdump(self, d):
        d['textid'] = []
        for tid in self.projecttextid_set.all():
            d['textid'].append(tid.textid)

        return d

    # project.post_export
    def UNUSED_post_export(self, d):
        return self.transaction_postdump(d)

    # project.transaction_postload
    def transaction_postload(self, d):

        super(Project, self).transaction_postload(d)

        self.save()  # need to save before add other fields

        if 'textid' in d:
            textids = json.loads(d['textid'])
            self.projecttextid_set.all().delete()
            for tid in textids:
                self.addtextid(tid)

    # project.post_import
    def UNUSED_post_import(self, d):
        self.save()
        if 'textid' in d:
            textids = d['textid']
            # self.projecttextid_set.all().delete()
            for tid in textids:
                self.addtextid(tid)

    # project.uniqname
    def uniqname(self, basename):

        def nameiterator(basename):
            yield basename
            for i in range(1, 10000):
                yield basename + '.' + str(i)

        for tryname in nameiterator(basename):
            # exists?
            try:
                i = self.get_indicator(tryname)
            except ObjectDoesNotExist:
                # no such name! great
                return tryname


class ProjectTextID(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    textid = models.CharField(max_length=200, unique=True)

    def __str__(self):
        return self.textid


class ProjectInvite(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    expires = models.DateTimeField(default=timezone.now, blank=True)
    secret = models.CharField(max_length=200)
    email = models.CharField(max_length=200, null=True)  # if set, it will be seen from control panel
    total = models.IntegerField(null=True)
    left = models.IntegerField(null=True)
    rid = models.CharField(max_length=100, default='', db_index=True)

    def __str__(self):

        if not self.email:
            return "Common invitation to {} ({}/{}) code: {}".format(self.project.name, self.left, self.total,
                                                                     self.secret)
        else:
            return "Personal invitation {} to {} ({}/{})".format(self.email, self.project.name, self.left, self.total)

    # projectnivide.dumpall
    @staticmethod
    def dumpall():
        for pi in ProjectInvite.objects.all():
            print(pi)

    # projectinvite.cron
    @staticmethod
    def cron():
        # delete invitations with 0 invites left
        ProjectInvite.objects.filter(total__isnull=False, left=0).delete()
        ProjectInvite.objects.filter(expires__lt=timezone.now()).delete()

    # projectinvite.create
    @staticmethod
    def create(project, expires, email, total):
        l = 20
        secret = project.get_textid() + ':' + ''.join(
            random.choice(string.ascii_lowercase + string.digits) for _ in range(l))
        inv = ProjectInvite.objects.create(project=project, expires=expires, secret=secret, email=email, total=total,
                                           left=total)
        inv.tsave()
        return inv

    @staticmethod
    def usecode(user, code):
        pi = ProjectInvite.objects.filter(secret=code).first()
        if pi and pi.project.ci == myci():
            # for local
            status, err = pi.accept(user)
            if status:
                pi.save()
            return (status, err)
        else:
            return ProjectInvite.remote_usecode(user, code)
            # return (False,"Invitation code is invalid or inactive")

    @staticmethod
    def remote_usecode(user, secret):
        textid = secret.split(':')[0]
        log.info('remote_accept textid: {} code: {}'.format(textid, secret))
        p = Project.get_by_textid(textid)
        if p is None:
            return (False, 'Dont know this project')
        rs = RemoteServer(ci=p.ci)

        try:
            data = rs.accept_invite(user.email, secret)
        except:
            return (False, 'Something wrong')

        ie = Impex()
        ie.set_verbosity(0)
        ie.preimport_cleanup(data)
        ie.import_data(data)
        return (True, 'Welcome!')

    # projectinvite.tsave
    def tsave(self):
        self.touch()
        self.save()

    # projectinvite.touch
    def touch(self, touchall=False, parent=None):
        set_rid(self)
        # no mtime
        # self.mtime = timezone.now()

        # te = TransactionEngine()
        # te.update_instance(self)

        if touchall:
            self.save()
            self.project.touch(touchall)

    # projectinvite.accept
    def accept(self, user):
        # check if local or remote
        if self.project.ci == myci():
            return self.local_accept(user)
        else:
            return self.remote_accept(user)

    def remote_accept(self, user):
        textid = self.secret.split(':')[0]
        log.info('remote_accept textid: {} code: {}'.format(textid, self.secret))
        p = Project.get_by_textid(textid)
        if p is None:
            return (False, 'Dont know this project')
        rs = RemoteServer(ci=p.ci)

        try:
            data = rs.accept_invite(user.email, self.secret)
        except:
            return (False, 'Something is wrong')

        # print "accept project after invite"
        # print json.dumps(data, indent=4)

        ie = Impex()
        ie.set_verbosity(0)
        ie.preimport_cleanup(data)
        # print "after cleanup:"
        # ProjectInvite.dumpall()

        ie.import_data(data)
        # print "after import:"
        # ProjectInvite.dumpall()

        return (True, 'Welcome!')

    #
    # projectinvite.local_accept
    #
    # accepts invitation (adds to project)
    # returns error string or None
    # must save ti after this! (because it may change self.left)
    #

    def local_accept(self, user):

        log.info('local accept PI for {}'.format(user.email))
        # check if invitation matches user or open
        if self.email and self.email != user.email:
            return (False, "attempt to use other user invitation")

        if self.left == 0:
            return (False, "attempt to use used invitation (left is zero)")

        if timezone.now() > self.expires:
            return (False, "attempt to use expired invitation")

        can, err = self.project.can_accept(user)

        if not can:
            print("can_accept returned false with error:", err)
            return (False, err)

        # now use it
        # add user to project
        log.info('ok, create projectmember')
        ProjectMember.objects.create(project=self.project, email=user.email, iadmin=False)

        # reduce left if apply
        if self.left:
            self.left -= 1

        log.info("left: {}".format(self.left))

        if self.left:
            log.info('self-save PI')
            self.save()
        else:
            log.info('self-delete PI')
            self.delete()

        return (True, "Accepted user {} to project {}".format(
            user.username, self.project.name))


class ProjectAccessKey(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    key = models.CharField(max_length=200)
    remark = models.CharField(max_length=200)

    # projectaccesskey.generate
    def generate(self, remark):
        alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits
        self.key = ''.join(random.choice(alphabet) for _ in range(40))
        self.remark = remark

    def preview(self):
        return self.key[:4]


class Policy(TransModel):
    name = models.CharField(max_length=200)
    #    period = models.IntegerField(default=3600)
    period = models.CharField(max_length=200, default='1h')

    #    patience = models.IntegerField(default=1200) # 1h + 20min, used only for passive
    patience = models.CharField(default='300s', max_length=200)  # 1h + 20min, used only for passive

    # wipe = models.IntegerField(default=86400 * 60)
    autocreate = models.BooleanField(default=True)
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    secret = models.CharField(max_length=200, default="", blank=True)
    smtpupdate = models.BooleanField(default=True)
    httpupdate = models.BooleanField(default=True)
    retry_schedule = models.CharField(max_length=200, default="", blank=True)
    recovery_retry_schedule = models.CharField(max_length=200, default="", blank=True)
    reduction = models.CharField(max_length=200, default="", blank=True)
    mtime = models.DateTimeField(auto_now=True)
    url_statuschange = models.CharField(max_length=200, default='')

    # rid = models.CharField(max_length=100, default='', db_index=True)

    class Meta:
        verbose_name_plural = 'Policies'

    # policy.init
    def init(self):
        pass

    def __str__(self):
        return "{} ({})".format(self.name, self.period)

    @classmethod
    def validname(cls, name):
        if not name:
            raise ValueError('Policy must have non-empty name')



    # policy.fix
    def fix(self, verbose=False):
        # fix record, e.g. details
        if verbose:
            print("{} my ci: {}, project ci: {}".format(
                "DIFF" if self.ci != self.project.ci else "match",
                self.ci, self.project.ci
            ))

        if self.ci != self.project.ci:
            if verbose:
                print("policy {} ci: {}, project {}/{} ci: {}".format(self, self.ci,
                                                                      self.project.get_textid(), self.project.name,
                                                                      self.project.ci))
            self.ci = self.project.ci

    # policy.get_period
    #
    # return period in seconds
    #
    # does NOT checks against minperiod
    #
    def get_period(self):
        period = timesuffix2sec(self.period)
        return max(period, self.project.minperiod())

    # return retry schedule as list of numbers (seconds)
    def get_retry_schedule(self, recovery=False):
        sch = list()

        if recovery:
            schedule = self.recovery_retry_schedule
        else:
            schedule = self.retry_schedule

        for time in filter(None, schedule.split(' ')):
            sec = timesuffix2sec(time)
            sch.append(sec)

        return sch

    @staticmethod
    def validate_retry_schedule(schedule):
        for time in filter(None, schedule.split(' ')):
            time = time.lower()
            r = re.match('(\d+)(h|m|s|hour|hours|hr|min|minute|minutes|sec|seconds)?$', time)
            if r is None:
                raise ValueError('Cannot parse \'{}\'. Valid examples are: 10s, 5m, 2h'.format(time))

    @staticmethod
    def validate_reduction(reduction):
        try:
            ts = TimeStr(reduction, validator=lambda x: isinstance(timesuffix2sec(x), int))
        except (ValueError, IndexError):
            raise (ValueError(_("Incorrect alert reduction. Example:\n0s or\n0s 00:30-02:00 5m 14:00-14:30 10s")))

    def validate_patience(self, pstr):
        timesuffix2sec(pstr)

    def validate_period(self, pstr):
        p = timesuffix2sec(pstr)
        # minperiod WITH perks
        minperiod = self.project.owner.profile.getarg('minperiod')
        # print "validate period {} against minperiod {}".format(p, minperiod)
        if p < minperiod:
            raise ValueError(_('Period {}s is less then minperiod {}s').format(pstr, minperiod))

    # policy.touch
    def touch(self, touchall=False):
        set_rid(self)

        self.mtime = timezone.now()
        # te = TransactionEngine()
        # te.update_instance(self)

        if touchall:
            self.save()
            self.project.touch(touchall)


    # policy.tsave
    def tsave(self):
        uni_tsave(self)

    def checkip(self, ipstr):
        try:
            ip = IPAddress(ipstr)
            for ps in self.policysubnet_set.all():
                subnet = IPNetwork(ps.subnet)
                if ip in subnet:
                    return True
        except AddrFormatError:
            return False
        return False

    # policy.cron
    @staticmethod
    def cron():
        pass
        # walk over all policies
        # for p in Policy.objects.all():
        #    wipe = p.wipe
        #    moment = timezone.now() - datetime.timedelta(seconds=wipe)
        #    for i in p.project.indicator_set.filter(updated__lt=moment):
        #        log.info('wipe indicator {} from {}:{}, policy {} wipe {} '
        #                 'updated: {} age {}'.format(
        #            i, p.project.owner.username, p.project.name, p.name, wipe, i.updated, timezone.now() - i.updated))
        #        i.delete()

    # policy.backup
    def backup(self):
        s = {}
        s['mtime'] = dt2unixtime(self.mtime)

        for attr in ['name', 'period', 'patience', 'autocreate', 'secret', 'smtpupdate', 'httpupdate']:
            s[attr] = getattr(self, attr)
        s['subnets'] = []
        for sn in self.policysubnet_set.all():
            s['subnets'].append(sn.backup())
        return s

    # policy.restore
    @staticmethod
    def restore(project, s):
        if not 'name' in s:
            return None
        policy = Policy.objects.filter(name=s['name']).first()
        if policy:
            return None
        policy = Policy()
        policy.project = project

        for attr in ['name', 'period', 'patience', 'autocreate', 'secret', 'smtpupdate', 'httpupdate']:
            if attr in s:
                setattr(policy, attr, s[attr])
            else:
                print("no such attr '{}'!".format(attr))
                print(s)
                return None

        policy.save()

        for sn in s['subnets']:
            PolicySubnet.restore(policy, sn)
        return policy

    # policy.transaction_postdump
    def transaction_postdump(self, d):
        d['subnets'] = []
        for sn in self.policysubnet_set.all():
            d['subnets'].append(sn.backup())

        return d

    # policy.transaction_postload
    def transaction_postload(self, d):
        super(Policy, self).transaction_postload(d)

        self.save()
        if 'subnets' in d:
            sn = json.loads(d['subnets'])
            self.policysubnet_set.all().delete()
            for psn in sn:
                PolicySubnet.restore(self, psn)

    # policy.numindicators_total
    def numindicators_total(self):
        # ???
        c = self.project.indicator_set.filter(policy=self).count()
        return c

    def numindicators_enabled(self):
        # ???
        c = self.project.indicator_set.filter(policy=self, disabled=False).count()
        return c

    def numindicators_disabled(self):
        # ???
        c = self.project.indicator_set.filter(policy=self, disabled=True).count()
        return c

    # policy.rawdatastruct
    def rawdatastruct(self):
        s = dict()
        s['id'] = self.id
        s['name'] = self.name
        s['period'] = self.period
        s['patience'] = self.patience
        return s


class PolicySubnet(models.Model):
    policy = models.ForeignKey(Policy, on_delete=models.CASCADE)
    subnet = models.CharField(max_length=200)
    remark = models.CharField(max_length=200)

    # policysubnet.backup
    def backup(self):
        s = {}
        s['subnet'] = self.subnet
        s['remark'] = self.remark
        return s

    # policysubnet.restore
    @staticmethod
    def restore(policy, s):
        # print "policysubnet.restore, s:",repr(s)

        sn = PolicySubnet()
        sn.policy = policy
        sn.subnet = s['subnet']
        sn.remark = s['remark']
        sn.save()

    def __str__(self):
        return "{}: {} ({})".format(self.policy.name, self.subnet, self.remark)


class CheckMethod(models.Model):
    name = models.CharField(max_length=200)
    codename = models.CharField(max_length=200)
    desc = models.TextField()
    enabled = models.BooleanField(default=True)
    remote = models.BooleanField(default=False)

    passive_list = ['heartbeat', 'numerical', 'string']

    cmconf = {
        "sslcert": {
            "name": "SSL Certificate check",
            "remote": True,
            "args": {
                "host": {
                    "textname": "Hostname to check, e.g. www.okerr.com",
                    "desc": "no desc yet...",
                    "default": "www.okerr.com"
                },
                "port": {
                    "textname": "port",
                    "desc": "no desc yet...",
                    "default": "443"
                },
                "days": {
                    "textname": "min days to expire",
                    "desc": "ERR will be set if cert expires sooner",
                    "default": "20"
                },
                "options": {
                    "textname": "Options: ssl_noverify addr=1.2.3.4",
                    "desc": "Options: ssl_noverify addr=1.2.3.4",
                    "default": ""
                },

                #                    "ciphers": {
                #                        "textname": "SSL Ciphers",
                #                        "desc": "OpenSSL ciphers",
                #                        "default": "DEFAULT:!ECDH"
                #                        "default": "EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5"
                #                    }

            }  # sslcert.args
        },  # sslcert

        "string": {
            "name": "String",
            "remote": False,
            "args": {
                "str": {
                    "textname": "str",
                    "desc": "string/text data",
                    "default": ""
                },
                "patience": {
                    "textname": "patience",
                    "desc": "override policy 'patience'",
                    "default": ""
                },
                "secret": {
                    "textname": "secret",
                    "desc": "override policy 'secret'",
                    "default": ""
                },
                "options": {
                    "textname": "Options",
                    "desc": "text, dynamic, empty_ok, empty_err, reinit",
                    "default": ""
                }
            }  # strings.args
        },  # string

        "heartbeat": {
            "name": "Heartbeat",
            "remote": False,
            "args": {
                "patience": {
                    "textname": "patience",
                    "desc": "override policy 'patience'",
                    "default": ""
                },
                "secret": {
                    "textname": "secret",
                    "desc": "override policy 'secret'",
                    "default": ""
                },
            }  # heartbeat.args
        },  # heartbeat

        "numerical": {
            "name": "Numerical",
            "remote": False,
            "args": {
                "current": {
                    "textname": "value",
                    "desc": "Current value",
                    "default": ""
                },
                "patience": {
                    "textname": "patience",
                    "desc": "override policy 'patience'",
                    "default": ""
                },
                "secret": {
                    "textname": "secret",
                    "desc": "override policy 'secret'",
                    "default": ""
                },
                "minlim": {
                    "textname": "minlim",
                    "desc": "minimal limit",
                    "default": ""
                },
                "maxlim": {
                    "textname": "maxlim",
                    "desc": "maximal limit",
                    "default": ""
                },
                "diffmin": {
                    "textname": "diffmin",
                    "desc": "minimal difference",
                    "default": ""
                },
                "diffmax": {
                    "textname": "diffmax",
                    "desc": "maximal difference",
                    "default": ""
                }  #
            }  # numerical.args
        },  # numerical
        "logic": {
            "name": "Logical expression",
            "remote": False,
            "args": {
                "expr": {
                    "textname": "Logical expression",
                    "desc": "Python-style logical expression",
                    "default": "True"
                },
                "dump": {
                    "textname": "Dump values of these variables",
                    "desc": "comma-separate list, e.g. age['ERR:errage'], s['myindicator']",
                    "default": ""
                },
                "init": {
                    "textname": "These variables (comma-separated) will be set to 0 initially. ",
                    "desc": "comma-separate list, e.g. age['ERR:errage'], s['myindicator']",
                    "default": ""
                },
            }  # logic.args
        },  # logic
        "ping": {
            "name": "Ping",
            "remote": True,
            "args": {
                "host": {
                    "textname": "host",
                    "desc": "Remote host",
                    "default": "127.0.0.1"
                }
            }
        },
        "tcpport": {
            "name": "TCP Port",
            "remote": True,
            "args": {
                "host": {
                    "textname": "host",
                    "desc": "Remote host",
                    "default": "127.0.0.1"
                },
                "port": {
                    "textname": "port",
                    "desc": "TCP Port",
                    "default": "80"
                },
                "substr": {
                    "textname": "Substring",
                    "desc": "Look for this substring in server banned ",
                    "default": ""
                },
            }  # tcpport.args
        },  # tcpport
        "sha1static": {
            "remote": True,
            "name": "HTTP SHA1 hash static",
            "args": {
                "url": {
                    "textname": "URL",
                    "desc": "URL",
                    "default": "https://okerr.com/"
                },
                "hash": {
                    "textname": "hash",
                    "desc": "SHA1 hash",
                    "default": ""
                },
                "options": {
                    "textname": "Options: ssl_noverify addr=1.2.3.4",
                    "desc": "Options: ssl_noverify addr=1.2.3.4",
                    "default": ""
                },
            }
        },  # sha1 static

        "sha1dynamic": {
            "name": "HTTP SHA1 hash dynamic",
            "remote": True,
            "args": {
                "url": {
                    "textname": "URL",
                    "desc": "URL",
                    "default": "https://okerr.com/"
                },
                "hash": {
                    "textname": "hash",
                    "desc": "SHA1 hash",
                    "default": ""
                },
                "options": {
                    "textname": "Options: ssl_noverify addr=1.2.3.4",
                    "desc": "Options: ssl_noverify addr=1.2.3.4",
                    "default": ""
                },

            }
        },  # sha1 dynamic

        "httpstatus": {
            "name": "HTTP status code",
            "remote": True,
            "args": {
                "url": {
                    "textname": "URL",
                    "desc": "URL",
                    "default": "https://okerr.com/"
                },
                "options": {
                    "textname": "Options: ssl_noverify addr=1.2.3.4",
                    "desc": "Options: ssl_noverify addr=1.2.3.4",
                    "default": ""
                },
                "status": {
                    "textname": "status",
                    "desc": "HTTP status code",
                    "default": "200"
                },
            }  # httpstatus.args
        },  # httpstatus

        "httpgrep": {
            "name": "HTTP grep",
            "remote": True,
            "args": {
                "url": {
                    "textname": "URL",
                    "desc": "URL",
                    "default": "https://okerr.com/"
                },
                "musthave": {
                    "textname": "must have",
                    "desc": "this text must present on page",
                    "default": ""
                },
                "mustnothave": {
                    "textname": "must not have",
                    "desc": "this text must NOT present on page",
                    "default": "Error"
                },
                "options": {
                    "textname": "Options: ssl_noverify addr=1.2.3.4",
                    "desc": "Options: ssl_noverify addr=1.2.3.4",
                    "default": ""
                },
            }  # httpgrep.args
        },  # httpgrep

        "whois": {
            "name": "WHOIS (domain expiration)",
            "remote": True,
            "args": {
                "domain": {
                    "textname": "domain",
                    "desc": "domain name",
                    "default": "okerr.com"
                },
                "days": {
                    "textname": "days",
                    "desc": "ERR if will expire in less then DAYS",
                    "default": "30"
                },
            }  # whois.args
        },  # whois

        "dns": {
            "name": "DNS resolving",
            "remote": True,
            "args": {
                "host": {
                    "textname": "hostname or IP address",
                    "desc": "",
                    "default": "okerr.com"
                },
                "type": {
                    "textname": "DNS query type ('A', 'MX', ...) or 'reverse' or 'DNSBL dnsbl.example.com'",
                    "desc": "",
                    "default": "A"
                },
                "options": {
                    "textname": "options",
                    "desc": "",
                    "default": "init dynamic"
                },
                "value": {
                    "textname": "Current value. Set empty and 'init' in options to reinitialize",
                    "desc": "",
                    "default": ""
                },
            }  # dns.args
        },  # dns

        "dnsbl": {
            "name": "Antispam DNS Block List",
            "remote": True,
            "args": {
                "host": {
                    "textname": "hostname or IP address",
                    "desc": "",
                    "default": "okerr.com"
                },
                "skip": {
                    "textname": "skip these DNSBL zones (separated by comma and/or spaces). e.g.\nrbl.example.com rbl2.example.com",
                    "desc": "",
                    "default": ""
                },
                "extra": {
                    "textname": "add these DNSBL zones (separated by command and/or spaces) e.g.\nrbl.example.com rbl2.example.com",
                    "desc": "",
                    "default": ""
                },
            }  # dnsbl.args
        },  # dnsbl
    }  # cmconf structure

    @staticmethod
    def codenames():
        # cn= ['heartbeat','numerical','sslcert','string','logic','sha1dynamic','sha1static','ping','tcpport','httpstatus','httpgrep']
        # return cn
        return CheckMethod.getCheckMethods().keys()

    # cm.passive
    def passive(self):
        return self.codename in self.passive_list

    # cm.active
    def active(self):
        return not self.passive()

    # cm.retrymethod
    # true if this method is worth to retry
    def retrymethod(self):
        return not self.codename in ['heartbeat', 'numerical', 'string', 'logic']

    def __str__(self):
        return self.name

    # checkmethod.action / cm.action
    # used from process, indicator.action
    def action(self, i):

        if i.cm.codename == 'logic':
            (newstatus, details) = self.action_logic(i)
            i.register_result(newstatus, details, source="okerr-process")
        else:
            # any heartbeat indicator expired
            i.register_result('ERR', 'No heartbeat', source="okerr-process", can_retry=False)

        i.save()

    def action_logic(self, i):
        expr = i.getarg('expr', 'True')
        dump = i.getarg('dump', '')
        context = i.pdatastruct()

        # fill details by dump
        details = ''
        for ctxvar in dump.split(','):
            ctxvar = ctxvar.strip()
            if not ctxvar:
                # empty line
                continue
            success, result = evalidate.safeeval(ctxvar, context)
            if success:
                details += "{}={} ".format(ctxvar, result)
            else:
                log.debug('evalidate dump safeeval {} failed: {}'.format(repr(ctxvar), result))
                i.problem = True
                return ("ERR", result)

        success, result = evalidate.safeeval(expr, context)
        if success:
            if result:
                return ('OK', details)
            else:
                return ('ERR', details)
        else:
            log.debug('evalidate expr safeeval failed: {}'.format(result))
            i.problem = True
            return ("ERR", result)

    def mycmconf(self):
        return self.getCheckMethods()[self.codename]

    def argnames(self):
        cc = self.mycmconf()
        return cc['args'].keys()

    @classmethod
    def getCheckMethods(cls):
        return cls.cmconf

    @staticmethod
    def get_default_argvalue(cmname, argname):
        return CheckMethod.cmconf[cmname]['args'][argname]['default']

    @staticmethod
    def reinit_checkmethods(really=False, quiet=False):

        cmconf = CheckMethod.getCheckMethods()

        for cmname in cmconf:

            cmc = cmconf[cmname]

            # print "check checkmethod {}".format(cmname)
            try:
                cm = CheckMethod.objects.get(codename=cmname)
            except ObjectDoesNotExist:
                if not quiet:
                    print("No checkmethod '{}'! Create.".format(cmname))
                if really:
                    cm = CheckMethod.objects.create(codename=cmname)
                else:
                    print("not really")

            if cm.name != cmc['name']:
                if not quiet:
                    print("bad name '{}', change to '{}'".format(cm.name, cmconf[cmname]['name']))
                if really:
                    cm.name = cmconf[cmname]['name']
                    cm.save()
                else:
                    print("not really")

            if cm.remote != cmc['remote']:
                if not quiet:
                    print("fix remote to", cmc['remote'])
                cm.remote = cmc['remote']
                cm.save()

            for ca in cm.checkarg_set.all():
                if ca.argname in cmc['args']:
                    # print "exist ca:",ca
                    pass
                else:
                    if not quiet:
                        print("bad arg: '{}'".format(ca))
                    if really:
                        ca.delete()
                        print("DELETED {}.{}".format(cmname, ca.argname))
                    else:
                        print("not really")

            for argname in cmc['args']:
                cma = cmc['args'][argname]
                # print "{} CheckArg {}".format(cmname, argname)

                save = False

                try:
                    cmarg = CheckArg.objects.get(cm=cm, argname=argname)
                except ObjectDoesNotExist:
                    if not quiet:
                        print("create... {}.{}".format(cmname, argname))
                    if really:
                        cmarg = CheckArg.objects.create(cm=cm, argname=argname)
                    else:
                        print("not really")

                if cmarg.default != cma['default']:
                    if not quiet:
                        print("fix {}:{}:{} '{}' -> '{}'".format(cmname, argname, 'default', cmarg.default,
                                                                 cma['default']))
                    cmarg.default = cma['default']
                    save = True

                if cmarg.textname != cma['textname']:
                    if not quiet:
                        print("fix {}:{}:{} '{}' -> '{}'".format(cmname, argname, 'textname', cmarg.textname,
                                                                 cma['textname']))
                    cmarg.textname = cma['textname']
                    save = True

                if cmarg.desc != cma['desc']:
                    if not quiet:
                        print("fix {}:{}:{} '{}' -> '{}'".format(cmname, argname, 'desc', cmarg.desc, cma['desc']))
                    cmarg.desc = cma['desc']
                    save = True

                if save:
                    if really:
                        if not quiet:
                            print("Save\n")
                        cmarg.save()
                    else:
                        print("not really")


class CheckArg(models.Model):
    cm = models.ForeignKey(CheckMethod, on_delete=models.CASCADE)
    argname = models.CharField(max_length=200)  # e.g. addr
    textname = models.CharField(max_length=200, default='')  # e.g. address of remote server
    desc = models.TextField(default='', blank=True)  # e.g. If packetloss will be over this number, blah-blah-blah
    default = models.CharField(max_length=200, default='', blank=True)

    def __str__(self):
        return self.argname


class Indicator(TransModel):
    #    def validate_status(value):
    #        if value != 'OK' and value != 'ERR' and value != 'WARN':
    #            raise ValidationError('status must be OK, ERR or WARN')

    name = models.CharField(max_length=200, db_index=True)
    policy = models.ForeignKey(Policy, on_delete=models.PROTECT)
    desc = models.TextField(blank=True)
    # _status = models.CharField(max_length=20, validators=[self.validate_status], default='OK', db_column='status') # Last status, actually enum 'OK','WARN','ERR'

    _status = models.CharField(max_length=20, default='OK',
                               db_column='status')  # Last status, actually enum 'OK','WARN','ERR'
    prevstatus = models.CharField(max_length=20, blank=True)
    details = models.CharField(max_length=200, blank=True)
    #    d = models.DateTimeField(default=timezone.now, blank=True) # WTF? delete it?
    created = models.DateTimeField(auto_now_add=True)  # status updated (maybe not changed)
    changed = models.DateTimeField(default=timezone.now, blank=True)  # status changed
    updated = models.DateTimeField(default=timezone.now, blank=True)  # status updated (maybe not changed)
    mtime = models.DateTimeField(default=timezone.now)  # indicator modified (not status changed!)
    maintenance = models.DateTimeField(default=None, null=True)
    dead = models.BooleanField(default=False)  # true only for passive ERR indicators
    disabled = models.BooleanField(default=False)  # do not run tests, do not send alerts
    silent = models.BooleanField(default=False)  # do not sent alerts even if ERR (but run tests)
    problem = models.BooleanField(default=False)  # true if something wrong with id, e.g. wrong python usercode
    #    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    cm = models.ForeignKey(CheckMethod, on_delete=models.PROTECT, null=False, blank=False)
    # newchange = models.BooleanField(default=False)
    # scheduled action
    scheduled = models.DateTimeField(default=timezone.now, blank=True)
    # expected (scheduled could be expected + patience)
    expected = models.DateTimeField(default=timezone.now, blank=True, null=True)  # expected could be null
    lockpid = models.IntegerField(null=True)
    lockat = models.DateTimeField(null=True, blank=True)
    keypath = models.CharField(max_length=255, default=None, null=True)
    origkeypath = models.CharField(max_length=255, default=None, null=True)
    retry = models.IntegerField(default=0, null=True)  # how many retries are done
    last_fail_machine = models.CharField(max_length=200, blank=True, null=True,
                                         default='')  # machine which gave last failure (for active)
    jtags = models.CharField(default='[]', max_length=2000)
    jiargs = models.CharField(default='{}', max_length=2000)
    jcheckargs = models.CharField(default='{}', max_length=2000)
    location = models.CharField(max_length=200, default='', db_index=True)

    minpatience = 300  # no actions for delay lower then minpatience

    upname_suffix = "-up"

    class Meta:
        ordering = ['name']
        index_together = [
            ["project", "name"],
        ]
        unique_together = ('name', 'project')

    def get_fullname(self):
        return '{}@{}'.format(self.name, self.project.get_textid())

    @classmethod
    # indicator unlock_old
    def unlock_old(cls, td=None):
        # log.info('unlocking....')
        now = timezone.now()

        with transaction.atomic():
            if td is None:
                log.debug('onlock all records')
                uq = cls.objects.select_for_update().filter(lockpid__isnull=False)
            else:
                log.debug('unlock old locked records ({} ago)'.format(td))
                uq = cls.objects.select_for_update().filter(lockpid__isnull=False, lockat__lt=now - td)
            uc = uq.update(lockpid=None, lockat=None)
        log.debug("unlocked {} records".format(uc))

    # indicator.lock
    def lock(self, value):
        self.lockpid = value
        self.lockat = timezone.now()

    # indicator.cron
    @classmethod
    def cron(cls):
        # indicator cron
        cls.unlock_old(datetime.timedelta(0, 5))
        # delete old deleted_at indicators

        time_threshold = timezone.now() - datetime.timedelta(days=10)

        for i in cls.objects.filter(deleted_at__lt=time_threshold):
            log.info("reap indicator {} {}".format(i.project.get_textid(), i.name))
            i.delete()

    def get_status(self):
        return self._status

    # indicator.okerrm
    # DISABLED MAINTENANCE /*SILENT*/ OK ERR
    def okerrm(self):
        if self.disabled:
            return 'DISABLED'
        elif self.maintenance:
            return 'MAINTENANCE'
        # elif self.silent:
        #     return 'SILENT'
        else:
            return self.status

    # indicator.tproc
    def tproc(self):
        data = dict()
        data['_task'] = 'tproc.indicator'
        data['id'] = self.id
        # data['rid'] = self.rid
        # data['pid'] = self.project.id
        # data['prid'] = self.project.rid
        data['textid'] = self.project.get_textid()
        data['name'] = self.name
        data['cm'] = self.cm.codename
        data['args'] = self.getargs()
        data['mtime'] = dt2unixtime(self.mtime)
        data['period'] = self.policy.get_period()
        data['throttle'] = max(
            int((self.policy.get_period() + self.get_patience()) / 2),
            300)  # min 300sec

        return data

    def apply_tproc(self, r, name='', location='', throttled=None):

        if r['status'] == 'ERR':
            self.last_fail_machine = name
        else:
            self.last_fail_machine = ''

        source = "{}".format(name)

        self.register_result(r['status'], r['details'], source=source, throttled=throttled)

        if r['problem']:
            self.log('{} set problem flag'.format(name),
                     typecode='indicator')
            self.problem = r['problem']

        for msg in r['logs']:
            self.log(msg)

        for msg in r['alerts']:
            self.alert(msg)

        for argname, argval in r['set_args'].items():
            # print "SET {} = {}".format(argname, argval)
            self.setarg(argname, argval)

    # indicator.transaction_postdump
    def transaction_postdump(self, d):
        # d['cm'] = self.cm.name
        d['cm'] = [self.cm.codename, self.getargs()]
        d['tags'] = self.usertags()
        # list()
        # for tag in self.indicatortag_set.all():
        #    d['tags'].append(tag.name)
        return d

    # indicator.post_export
    def UNUSED_post_export(self, d):
        pass
        # d['cm'] = [ self.cm.codename, self.getargs() ]
        # d['tags'] = self.usertags()

    # indicator.transaction_postload
    def transaction_postload(self, d):
        # d['cm'] = self.cm.name
        super(Indicator, self).transaction_postload(d)

        if 'cm' in d:
            try:
                codename, dargs = json.loads(d['cm'])
                self.cm = CheckMethod.objects.get(codename=codename)
                self.setargs(dargs)
            except ValueError:
                raise "JSON Error with checkmethod {}".format(d['cm'])
        if 'tags' in d:
            self.settags(json.loads(d['tags']))

    # indicator.post_import
    def UNUSED_post_import(self, d):
        codename, dargs = d['cm']
        self.cm = CheckMethod.objects.get(codename=codename)
        self.reanimate()

        self.save()
        self.setargs(dargs)

        self.settags(d['tags'])

    # indicator.syncbackup
    def syncbackup(self, sync, tstamp, parent):
        backup = sync.backup_helper(self, parent)
        backup['cm'] = self.cm.name
        backup['args'] = self.getargs()
        backup['tags'] = list()
        for tag in self.indicatortag_set.all():
            backup['tags'].append(tag.name)

        return backup

    # indicator.touch
    def touch(self, touchall=False):

        super(Indicator, self).touch()

        if (touchall):
            self.save()
            self.project.touch(touchall)

    # indicator.register_result
    # sets new status/details, properly handling retries
    def register_result(self, status, details='', can_retry=True, source='', throttled=None):
        self.details = details
        ok = status == 'OK'

        if source:
            source += ': '  # 'alpha: '

        if status == self._status:
            # confirm
            if throttled:
                self.log('{}confirmed {}: {} (x{})'.format(source, status, details, throttled))
            else:
                self.log('{}confirmed {}: {}'.format(source, status, details))

            if self.cm.passive():
                self.dead = not ok
            else:
                self.dead = False

            self.retry = 0
            self.updated = timezone.now()
            self.reschedule()
        else:
            # new status
            if can_retry:
                retry = self.schedule_retry(recovery=ok)
            else:
                retry = None

            # print "schedule {}: {}".format(self.name, retry)
            if retry:
                # retry needed
                # no need to reschedule, schedule_retry() already did this
                self.log('{}got {} > {} ({}), will retry in {}s'.format(source, self._status, status, details, retry))
            else:
                self.log('{}switch {} > {}: {}'.format(source, self._status, status, details))

                self.retry = 0
                if self.cm.passive() and status == 'ERR':
                    self.dead = True
                else:
                    self.dead = False

                if not self.disabled:
                    self.change(status)
                    # self._status = status
                    self.reschedule()

    # indicator.change
    def change(self, status):

        age = timezone.now() - self.changed

        self.alert(
            "Changed status {old} ({age}) -> {new} ({details})".format(old=self._status, age=shorttd(age), new=status, details=self.details),
            reduction=status,
            old_reduction=self.status
        )
        self.changed = timezone.now()
        self.updated = timezone.now()

        if not self.maintenance:
            # self.newchange=True
            changerec = IChange(indicator=self, oldstate=self._status, newstate=status)
            changerec.save()
            self.prevstatus = self._status

            #
            # process external webhook
            #
            if self.policy.url_statuschange:
                r = get_redis()

                if r:
                    data = {
                        'type': 'status_change',
                        'textid': self.project.get_textid(),
                        'name': self.name,
                        'old': self._status,
                        'new': status,
                        'details': self.details,

                        'unixtime': int(time.time()),
                        'time': timezone.now().strftime('%Y-%m-%d %H:%M:%S %Z (%z)')
                    }

                    task = {
                        'data': json.dumps(data),
                        'url': self.policy.url_statuschange
                    }

                    tryn = 0
                    success = False

                    while not success:
                        try:
                            i = r.incr('http_post_cnt')
                            keyname = "http_post:{}".format(i)
                            r.hmset(keyname, task)
                            r.lpush('http_post_list', keyname)
                            log.info('created post req {} {}'.format(keyname, self.policy.url_statuschange))
                            success = True
                        except redis.ConnectionError as e:
                            log.error("redis http_post failed ({}): {} (cwd: {})".format(tryn, str(e), os.getcwd()))
                            tryn += 1
                            time.sleep(0.5)
                            r = get_redis()

                else:
                    log.error("no redis from get_redis()")

        # change it
        self._status = status

        self.save()
        self.update_ddns()

    def update_ddns(self):
        # dyndns
        for ddrv in self.dyndnsrecordvalue_set.all():
            ddrv.ddr.set_value()
            # ddrv.ddr.save()
            ddrv.ddr.push_value()
            ddrv.ddr.save()

    def set_status(self, value):
        """
            change(or update same) status
            calc/set scheduled
        """

        # profile = Profile.objects.filter(user=self.user).get()
        # set value to default
        reok = re.compile('^ok|^good', re.IGNORECASE)
        rewarn = re.compile('^warn', re.IGNORECASE)
        reerr = re.compile('^err|^fail|^bad', re.IGNORECASE)

        # lr = LogRecord(project=self.project, indicator = self)

        if reok.match(value):
            newstatus = 'OK'
        elif rewarn.match(value):
            newstatus = 'WARN'
        elif reerr.match(value):
            newstatus = 'ERR'
        else:
            return

        now = timezone.now()
        if self._status == newstatus:
            # print "same status (%s)" % value
            # self.log("confirmed status %s" % (newstatus))
            pass
        else:
            # self.log("new status (%s -> %s)" % (self._status,newstatus))
            # do not check for maintenance flag here
            # alert() will do this
            self.alert("Changed status {old} -> {new} ({details})".format(old=self._status, new=newstatus,
                                                                           details=self.details))

            self.changed = now
            # self.newchange=True
            changerec = IChange(indicator=self, oldstate=self._status, newstate=newstatus)
            changerec.save()
            self.prevstatus = self._status

        period = self.policy.get_period()
        patience = self.get_patience()

        self._status = newstatus
        self.updated = now
        self.expected = now + datetime.timedelta(seconds=period)
        if self.cm.passive():
            self.scheduled = now + datetime.timedelta(seconds=period) + datetime.timedelta(seconds=patience)
        else:
            self.scheduled = now + datetime.timedelta(seconds=period) + datetime.timedelta(seconds=patience)

    status = property(get_status, set_status)

    @staticmethod
    # indicator.validname syntax check
    def validname(name):
        # must not be number
        # try:
        try:
            numname = int(name)
        except ValueError:
            # good name, not number
            pass
        else:
            # bad name, looks like number
            return False

        # '/' is good char, because used in names like df-/var
        badchars = ['<', '>', '%', '\\', '@']
        for ch in badchars:
            if ch in name:
                return False

        if '//' in name or name.startswith('/'):
            return False

        return True

    def predelete(self):
        # set deadname for logrecords
        LogRecord.objects.filter(indicator=self).update(indicator=None, deadname=self.name)

    def briefdetails(self):
        maxlen = 50
        if len(self.details) < maxlen:
            return self.details
        return self.details[0:maxlen] + '..'

    def uptimes(self):
        uptimes = {}
        uptimes['minute'] = self.uptime(60)
        uptimes['hour'] = self.uptime(3600)
        uptimes['day'] = self.uptime(86400)
        uptimes['month'] = self.uptime(30 * 86400)
        return uptimes

    def uptime(self, seconds):

        uptime = {'OK': 0, 'ERR': 0, 'maintenance': 0}

        lasttime = timezone.now()
        for irec in self.ichange_set.order_by('-created'):
            period = lasttime - irec.created
            period_s = int(period.total_seconds())
            #            print "period: {} sec".format(period_s)
            taketime = period_s  # modify, take possibly less
            if taketime > seconds:
                taketime = seconds

            state = irec.newstate

            uptime[state] += taketime

            lasttime = irec.created
            seconds -= taketime
            if seconds <= 0:
                break

        # now convert to percents
        total = uptime['OK'] + uptime['ERR'] + uptime['maintenance']

        if total > 0:
            for p in ['OK', 'ERR', 'maintenance']:
                # uptime[p] = "{:.3f}".format(uptime[p] * 100 / total)
                uptime[p] = uptime[p] * 100 / total
        else:
            # no data, use current
            if self.maintenance:
                uptime['maintenance'] = 100
            else:
                uptime[self._status] = 100
        return uptime

    def iadmin(self, user):
        if self.project.iadmin(user):
            return True

    def can_have_upper(self):
        return True

    # upper-level indicator name, just add ':up'
    def mkupname(self):
        return self.name + self.upname_suffix

    # lower level indicator name, return name without ':up'
    # or none if this name is not '*:up'
    def mkloname(self):
        if self.name.endswith(self.upname_suffix):
            return self.name[:-len(self.upname_suffix)]
        return None

    #
    #  return upper-level indicator (if exists)
    #   or none
    def upindicator(self):
        try:
            return Indicator.objects.get(name=self.mkupname(), project=self.project)
        except ObjectDoesNotExist:
            return None

    def loindicator(self):
        try:
            return Indicator.objects.get(name=self.mkloname(), project=self.project)
        except ObjectDoesNotExist:
            return None

    def realkeypath(self):
        if (self.origkeypath is None) or (self.keypath is None):
            return ''

        if self.keypath:
            fullkp = self.origkeypath + ':' + self.keypath
        else:
            fullkp = self.origkeypath

        try:
            rkp = self.project.keytree().resolve(fullkp)
        except KeyError:
            return ''

        if rkp is None:
            rkp = ''
        return rkp

    # indicator.enabled
    def enabled(self):
        return not self.disabled

    # indicator.enable
    # ret true if enabled (or false)
    def enable(self):
        # TODO do not enable too much
        self.disabled = False
        return not self.disabled

    # indicator.disable
    def disable(self):
        self.disabled = True
        return self.disabled

    # indicator.copyname
    def copyname(self):
        return self.project.uniqname(self.name + '-copy')

    # indicator.copy
    def copy(self, copyname):

        newname = self.project.uniqname(copyname)

        i = Indicator.create(
            project=self.project,
            idname=newname,
            cmname=self.cm.codename,
            policy=self.policy.name,
        )

        if i is None:
            log.info('failed to create indicator {} (from {})'.format(newname, i.name))
            return None

        i.maintenance = self.maintenance
        i.jcheckargs = self.jcheckargs
        i.ci = self.ci
        i.location = self.location

        i.save()
        return i

    #
    # return in patience arg (if exists)
    # or return policy patience
    #

    # indicator.get_patience
    def get_patience(self):
        try:
            patience = timesuffix2sec(self.getarg('patience'))
        except (ValueError, TypeError) as e:
            patience = timesuffix2sec(self.policy.patience)

        # minpatience
        if patience < self.minpatience:
            patience = 300

        return patience

    @staticmethod
    def iarglist():
        return ['star', 'subscribe']

    def getiarg(self, user, name, default=None):

        iargs = json.loads(self.jiargs)
        try:
            return iargs[user.email][name]
        except KeyError:
            return default

    def setiarg(self, user, name, value):
        iargs = json.loads(self.jiargs)

        if not user.email in iargs:
            iargs[user.email] = dict()

        iargs[user.email][name] = value
        self.jiargs = json.dumps(iargs)

    # indicator.log
    def log(self, message, typecode='unspecified'):
        LogRecord(
            project=self.project,
            indicator=self,
            typecode=LogRecord.get_typecode(typecode),
            message=message.replace('\n', ' ')).save()

    # indicator.alert
    def alert(self, message, created=None, reduction=None, old_reduction=None):
        # do not make alerts for silent
        self.log('ALERT:' + message, typecode="alert"),
        if self.silent:
            return

        if self.maintenance:
            return

        if created is None:
            created = timezone.now()

        # transforms to hashes

        if reduction is not None:
            reduction = hashlib.sha1(reduction.encode()).hexdigest()
        if old_reduction is not None:
            old_reduction = hashlib.sha1(old_reduction.encode()).hexdigest()

        if self.policy.reduction:
            if reduction:
                reducted = self.alertrecord_set.filter(reduction=old_reduction).delete()[0]
                if reducted:
                    # log.info("reducted {}+1 alert records".format(reducted))
                    return

            # release time
            ts = TimeStr(self.policy.reduction)
            delay = timesuffix2sec(ts.get_value())
            release = timezone.now() + datetime.timedelta(seconds=delay)
        else:
            release = timezone.now()

        for user in self.project.members():
            if self.getiarg(user, "subscribe") or user.profile.sendalert:
                AlertRecord(user=user, indicator=self, proto='mail', message=message,
                            created=created, reduction=reduction, release_time=release).save()
                if user.profile.telegram_chat_id:
                    # self.log('make tg alert for {}: {}'.format(user.username, message))
                    AlertRecord(user=user, indicator=self, proto='telegram', message=message,
                                created=created, reduction=reduction, release_time=release).save()

    # indicator.retest
    def retest(self):
        # retest only if not passive

        if self.disabled:
            return

        self.dead = False
        # if self.cm.passive(): # no retests for all passive methods
        #    return
        self.expected = timezone.now()

        if self.cm.passive():
            patience = self.get_patience()
            self.scheduled = timezone.now() + \
                             datetime.timedelta(seconds=patience)
        else:
            self.unlock()
            self.scheduled = timezone.now()
            self.last_fail_machine = ''

    def pending(self):
        # period = self.policy.period
        # minperiod = self.project.minperiod()
        # period=self.get_

        #        print "pending for i{}:{}".format(self.id,self.name)

        if self.cm.passive():
            if self.expected and timezone.now() > self.expected:
                return True
        else:
            if timezone.now() > self.scheduled + datetime.timedelta(seconds=settings.MQ_PROCESS_TIME):
                return True

        # if timezone.now()>self.updated + datetime.timedelta(seconds=period):
        #    return True

        return False

    def is_quick(self):
        # True if indicator is quick
        return timesuffix2sec(self.policy.period) <= settings.MQ_QUICK_TIME

    # indicator.schedule_retry
    #
    # schedules retry for active test, returns seconds if schedules to do retry, or None if no retries
    #
    def schedule_retry(self, recovery=False):
        if self.is_quick(): return None

        if not self.cm.active():
            # no retry schedule for passive
            return None

        sch = self.policy.get_retry_schedule(recovery)

        if len(sch) == 0:
            # no retry schedule
            return None

        # maybe too early. UNUSED?
        """
        if self.retry and self.expected and timezone.now() < self.expected:
            assert (False)
            # print('too early update for {} (retry: {})'.format(self.name, self.retry))
            return int((self.expected - timezone.now()).total_seconds())
        """

        try:
            delay = sch[self.retry]
            # can have new retry. e.g sch is 1 element, retry is 0
            # self.expected = timezone.now() + datetime.timedelta(seconds=delay)
            self.expected = None

            self.scheduled = timezone.now() + datetime.timedelta(seconds=delay)  # will make next retry at that time

            self.retry += 1
            return delay

        except IndexError:
            # No retries left
            self.retry = 0
            return None

    # indicator.transaction_reanimate()
    def transaction_reanimate(self):
        # print "reanimate",self,"status:",self.status
        self.updated = timezone.now()
        self.reschedule()

    # indicator.reanimate
    def reanimate(self):

        # self.updated = timezone.now()

        if self.cm.active():
            # speed-up re-check for active indicators
            self.retest()
        else:
            self.reschedule()

    @classmethod
    def get_next_active(cls):
        q = cls.objects.filter(lockpid__isnull=True, ci=myci(), problem=False, disabled=False, dead=False,
                               deleted_at__isnull=True, cm__remote=True).order_by('scheduled')
        i = q.first()
        if i:
            return i.scheduled
        else:
            return None

    @classmethod
    def update_tproc_sleep(cls):
        na = cls.get_next_active()
        redis = get_redis(settings.OKERR_REDIS_DB)

        if na:
            sleeptime = int(time.mktime(na.timetuple()) - time.time())
            if sleeptime > settings.TPROC_MAXSLEEP:
                sleeptime = settings.TPROC_MAXSLEEP
        else:
            sleeptime = settings.TPROC_MAXSLEEP

        if sleeptime > 0:
            redis.set('tproc_sleep', 1)
            redis.expire('tproc_sleep', sleeptime)
        else:
            redis.delete('tproc_sleep')

    # indicator.reschedule
    def reschedule(self):
        #
        # NEW
        #
        period = self.policy.get_period()

        # try if it's over user limits
        minperiod = self.project.minperiod()
        period = max(period, minperiod)

        if self.cm.passive():
            # for passive, add patience also
            self.scheduled = timezone.now() + datetime.timedelta(seconds=period + self.get_patience())
            self.expected = timezone.now() + datetime.timedelta(seconds=period)
        else:
            # active
            if self.policy.get_period() <= settings.MQ_QUICK_TIME:
                # quick active
                self.expected = timezone.now() + datetime.timedelta(
                    seconds=settings.MQ_THROTTLE_TIME)  # We expect to get result after this time
                self.scheduled = self.expected + datetime.timedelta(
                    seconds=settings.MQ_PROCESS_TIME)  # We will wait little longer
            else:
                # regular active
                self.expected = None  # None now, will be not none when send to sensor
                self.scheduled = timezone.now() + datetime.timedelta(seconds=period)

        return self.scheduled

    # indicator.reschedule
    def reschedule_UNUSED(self):
        period = self.policy.get_period()

        # try if it's over user limits
        minperiod = self.project.minperiod()
        period = max(period, minperiod)

        self.expected = timezone.now() + datetime.timedelta(seconds=period)

        patience = self.get_patience()
        if self.cm.passive():
            # for passive, add patience also
            self.scheduled = timezone.now() + datetime.timedelta(seconds=period + self.get_patience())
        else:
            self.scheduled = timezone.now() + datetime.timedelta(seconds=period + self.get_patience())

        return self.scheduled

    def agesec(self):
        return int((timezone.now() - self.updated).total_seconds())

    def statusagesec(self):
        return int((timezone.now() - self.changed).total_seconds())

    def age(self):
        sec = (timezone.now() - self.updated).total_seconds()
        return dhms((timezone.now() - self.updated).total_seconds())

    def statusage(self):
        return dhms((timezone.now() - self.changed).total_seconds())

    def age_short(self):
        sec = (timezone.now() - self.updated).total_seconds()
        return dhms_short((timezone.now() - self.updated).total_seconds())

    def statusage_short(self):
        return dhms_short((timezone.now() - self.changed).total_seconds())

    # indicator.__unicode__
    def __str__(self):
        return self.name + '@' + self.project.get_textid() + " (" + self.status + ")"

    # indicator.getargs (do not mix with getarg)
    def getargs(self, full=False):

        args = json.loads(self.jcheckargs)

        if full:
            cadict = self.cm.mycmconf()['args']
            out = dict(cadict)
            for name in out.keys():
                try:
                    out[name]['value'] = args[name]
                except KeyError:
                    out[name]['value'] = CheckMethod.get_default_argvalue(self.cm.codename, name)

            return out
        else:
            return args

        return out

    # indicator.setargS
    def setargs(self, args):

        self.save()
        for argname, argval in args.items():
            self.setarg(argname, argval)

    # indicator.clean_args
    def clean_args(self):
        vargs = self.cm.argnames()

        args = self.getargs()
        for k in args.keys():
            if not k in vargs:
                self.delarg(k)

    # indicator.fix
    def fix(self, verbose=False):
        # fix record, e.g. details
        maxlen = Indicator._meta.get_field('details').max_length
        if len(self.details) > maxlen:
            self.details = self.details[:maxlen - 2] + '..'

    def unlock(self):
        self.lockpid = None
        self.lockat = None

    # indicator.save
    def save(self, *args, **kwargs):
        self.fix()
        return super(Indicator, self).save(*args, **kwargs)
        # return models.Model.save(self)

    # indicator.tsave : touch and save
    def tsave(self):
        uni_tsave(self)

    # indicator.unlock and indicator.save
    def usave(self):
        # self.fix()
        self.unlock()
        self.save()

    # indicator.fulldump
    def fulldump(self, prefix=""):
        flags = []

        for flagname in ['dead', 'silent']:
            if getattr(self, flagname):
                flags.append(flagname)

        if timezone.now() >= self.scheduled:
            flags.append('NOW')

        # super(Indicator, self).fulldump()

        print(self.title())
        print("Details:", self.details)
        print("cm: {}".format(self.cm))

        print("Project:", self.project.id, repr(self.project.name), "main ID:", self.project.get_textid(), "owner",
              self.project.owner)

        if self.ci == myci():
            flags.append("MYCI")

        print("{prefix}created: {created} ({age} ago) mtime:{mtime}".format(
            prefix=prefix, created=shortdate(self.created), age=chopms(timezone.now() - self.created),
            mtime=dt2unixtime(self.mtime)))

        print("{prefix}updated: {updated} ({dt} ago)".format(prefix=prefix, updated=shortdate(self.updated),
                                                             dt=dhms((timezone.now() - self.updated).total_seconds())))

        if self.expected:
            print("{prefix}expected : {expected} ({left})".format(
                prefix=prefix, expected=shortdate(self.expected), left=chopms(self.expected - timezone.now())))
        else:
            print("{prefix}expected: {expected}".format(prefix=prefix, expected=self.expected))

        print("{prefix}scheduled: {sch} ({left}) flags: {flags} ci: {ci} ({ciline})".format(
            prefix=prefix, sch=shortdate(self.scheduled), left=chopms(self.scheduled - timezone.now()),
            flags=flags, ci=self.ci, ciline="my" if self.ci == myci() else "otherci"))

        if self.last_fail_machine:
            print("{prefix}Last fail: {lfm}".format(prefix=prefix, lfm=self.last_fail_machine))

        if self.location:
            print("{prefix}Location: {location!r}".format(prefix=prefix, location=self.location))

        for n in ['disabled', 'status', 'details', 'lockpid', 'lockat', 'retry']:
            print("{prefix}{name}: {value}".format(prefix=prefix, name=n, value=getattr(self, n)))

        print("{prefix}tags: {tags}".format(prefix=prefix, tags=self.tags()))

        args = self.getargs()

        print("Upper-level indicator:", self.upindicator())
        print("Lower-level indicator:", self.loindicator())
        print("orig keypath:", self.origkeypath)
        print("keypath:", self.keypath)

        for n, v in args.items():
            print("{}{} = {}".format(prefix, n, v))
        print("")

    # indicator.getopt
    # gets option from 'options' field
    def getopt(self, optname, argname='options', default=None):
        opts = self.getarg(argname)

        if not opts:
            return default

        opta = shlex.split(opts)
        optd = {}
        for o in opta:
            if '=' in o:
                k, v = o.split('=', 1)
            else:
                k = o
                v = True
            optd[k] = v

        if optname in optd:
            return optd[optname]

        return default

    def istext(self):
        return self.getopt('text')

    # indicator.getarg (do not mix with getargS)
    def getarg(self, argname, default=None):

        args = json.loads(self.jcheckargs)
        if argname in args:
            return args[argname]
        return default

    # convert int or str to unicode, strip, replace \r\n -> \n
    @staticmethod
    def fixarg(value):

        # if not basestring - make it
        if not isinstance(value, str):
            value = str(value)

        # if not isinstance(value, unicode):
        #    value = value.decode('utf8')

        # value = value.strip()
        value = value.replace('\r\n', '\n')
        value = value.strip('\r\n\t ')
        return value

    # indicator.setarg
    def setarg(self, argname, value):

        # valid argnames
        vargs = self.cm.argnames()
        if not argname in vargs:
            return None

        value = Indicator.fixarg(value)

        args = json.loads(self.jcheckargs)
        args[argname] = value
        self.jcheckargs = json.dumps(args)
        self.touch()
        return value

    # indicator.delarg
    def delarg(self, argname):
        args = json.loads(self.jcheckargs)
        del args[argname]
        self.jcheckargs = json.dumps(args)

    # user can be None if this is recovery from backup
    def startmaintenance(self, user=None):
        if self.maintenance:
            # no need, already set
            return

        changerec = IChange(indicator=self, oldstate=self._status, newstate="maintenance")
        changerec.save()
        if user:
            self.log("user {} set maintenance".format(user.username), typecode="indicator")
        self.maintenance = timezone.now()
        self.save()
        self.update_ddns()

    def stopmaintenance(self, user):
        if not self.maintenance:
            return

        if user:
            self.log("user {} stop maintenance".format(user.username), typecode="indicator")

        changerec = IChange(indicator=self, oldstate="maintenance", newstate=self._status)
        changerec.save()

        mtime = chopms(timezone.now() - self.maintenance)
        self.maintenance = None
        self.save()
        self.update_ddns()

    # indicators.flags
    def flags(self):
        flags = []
        if self.disabled:
            flags.append("disabled")
        elif self.status == "OK":
            flags.append("OK")
        else:
            flags.append("ERR")

        if self.pending():
            flags.append("pending")
        if self.maintenance:
            flags.append("maintenance")
        if self.silent:
            flags.append("silent")
        if self.problem:
            flags.append("problem")
        return flags

    # indicator.backup
    def backup(self):
        backup = {}
        backup['args'] = {}
        backup['name'] = self.name
        backup['cm'] = self.cm.codename
        backup['tags'] = self.usertags()
        backup['jcheckargs'] = self.getargs()

        if self.maintenance:
            backup['maintenance'] = True
        else:
            backup['maintenance'] = False

        backup['silent'] = self.silent
        backup['problem'] = self.problem
        backup['disabled'] = self.disabled
        backup['policy'] = self.policy.name

        return backup

    # indicator.rawdatastruct
    def rawdatastruct(self):
        s = dict()
        s['id'] = self.id
        s['name'] = self.name
        s['details'] = self.details

        s['disabled'] = self.disabled
        s['silent'] = self.silent
        s['status'] = self.status
        s['problem'] = self.problem

        s['policy'] = self.policy.id

        s['scheduled'] = dt2unixtime(self.scheduled)
        s['expected'] = dt2unixtime(self.expected)
        s['changed'] = dt2unixtime(self.changed)
        s['updated'] = dt2unixtime(self.updated)

        s['maintenance'] = dt2unixtime(self.maintenance)

        s['cm'] = self.cm.codename
        s['active'] = self.cm.active()

        # print "indicator.rawdatastruct: i{}:{} maintenance: {}".format(self.id, self.name, s['maintenance'])

        s['flags'] = self.flags()
        s['tags'] = self.tags()
        s['iargs'] = json.loads(self.jiargs)

        return s

    def pdatastruct(self):
        pds = self.project.datastruct()
        loi = self.loindicator()

        if loi:
            pds['lo'] = loi.datastruct()
        else:
            pds['lo'] = None

        #
        # set default values for logic indicators
        #
        if self.cm.codename == 'logic':
            initarg = self.getarg('init', '')
            for iarg in initarg.split(','):
                if not iarg:
                    continue
                iarg = iarg.strip()
                subdict = pds
                keys = re.findall('[a-zA-Z0-9\:\.]+', iarg)

                for key in keys[:-1]:
                    try:
                        subdict = subdict[key]
                    except KeyError:
                        subdict[key] = {}
                        subdict = subdict[key]

                if not keys[-1] in subdict:
                    subdict[keys[-1]] = 0

        return pds

    # indicator.datastruct
    #
    # used in logic expressions
    #
    def datastruct(self):
        s = {}
        s['id'] = self.id
        s['name'] = self.name
        s['status'] = self.status
        s['mtime'] = dt2unixtime(self.mtime)

        if self.status == 'OK' or self.silent:
            # OK or silent
            s['errage'] = s['uerrage'] = 0
        elif self.maintenance:
            # handled problem
            s['errage'] = self.statusagesec()
            s['uerrage'] = 0
        else:
            # unhandled problem
            s['errage'] = s['uerrage'] = self.statusagesec()

        s['age'] = self.agesec()
        s['statusage'] = self.statusagesec()
        s['patience'] = self.get_patience()
        if self.maintenance:
            s['maintenance'] = True
        else:
            s['maintenance'] = False
        return s;

    # indicator.fulldatastruct
    def fullDataStruct(self):
        s = {}
        s['id'] = self.id
        s['name'] = self.name
        s['status'] = self.status
        s['desc'] = self.desc

        s['details'] = self.details

        s['disabled'] = self.disabled
        s['silent'] = self.silent
        s['problem'] = self.problem

        s['policy'] = self.policy.id
        s['location'] = self.location

        s['scheduled'] = dt2unixtime(self.scheduled)
        s['expected'] = dt2unixtime(self.expected)
        s['changed'] = dt2unixtime(self.changed)
        s['updated'] = dt2unixtime(self.updated)

        s['maintenance'] = dt2unixtime(self.maintenance)

        s['flags'] = self.flags()
        s['tags'] = self.tags()

        if self.status == 'OK' or self.silent:
            # OK or silent
            s['errage'] = s['uerrage'] = 0
        elif self.maintenance:
            # handled problem
            s['errage'] = self.statusagesec()
            s['uerrage'] = 0
        else:
            # unhandled problem
            s['errage'] = s['uerrage'] = self.statusagesec()

        s['age'] = self.agesec()
        s['statusage'] = self.statusagesec()

        s['patience'] = self.get_patience()
        s['args'] = self.getargs()

        return s;

    # indicator.restore
    @staticmethod
    def restore(project, s):
        name = s['name']

        i = Indicator.objects.filter(project=project, name=s['name']).first()
        if i:
            return None

        # set checkmethod
        try:
            cm = CheckMethod.objects.get(codename=s['cm'])
        except CheckMethod.DoesNotExist:
            log.error('indicator.restore cannot find cm codename "{}"'.format(s['cm']))
            return None

        # create
        i = Indicator()
        p = Policy.objects.filter(project=project, name=s['policy']).first()
        if not p:
            log.error('indicator.restore cannot find policy {}'.format(p))
            return None
        i.policy = p
        i.cm = cm
        i.project = project
        i.save()

        i.name = s['name']
        i.silent = s['silent']
        i.disabled = s['disabled']
        if s['maintenance']:
            i.startmaintenance()
        i.problem = s['problem']

        # recover tags now
        for tag in s['tags']:
            i.settag(tag)

        for argname, argval in s['args'].items():
            i.setarg(argname, argval)

        i.save()
        return i

    # indicator.tagfilter
    # return True if match
    def tagfilter(self, tf):
        tags = self.tags()
        for tagname, tagvalue in tf.items():
            if tagvalue == '+' and not tagname in tags:
                # missing required tag. not match
                return False

            if tagvalue == '-' and tagname in tags:
                # has wrong tag. not match
                return False

        return True

    def filter(self, kvd):
        args = self.getargs()
        tags = self.usertags()

        for k, v in kvd.items():

            # indicator arguments
            if k in args:
                if args[k] == v:
                    continue
                else:
                    return False

            # tags
            if bool(k in self.tags()) == v:
                continue
            return False

        return True

    # indicator.tags
    def tags(self):
        tags = self.flags()

        # if not self.disabled:
        #    tags.append(self.status)

        tags.append(self.cm.codename)
        if self.cm.passive():
            tags.append('passive')
        else:
            tags.append('active')

        # maybe add 'CheckMe' tag
        if "problem" in tags \
                or "maintenance" in tags \
                or (("ERR" in tags) and not ("silent" in tags)):
            tags.append('ATTENTION')

        # add policy name
        tags.append("policy:" + self.policy.name)

        tags.extend(self.usertags())
        return tags

    def usertags(self):

        tags = json.loads(self.jtags)
        # tags=[]
        # for tag in self.indicatortag_set.all():
        #    tags.append(tag.name)
        return tags

    def settag(self, name):
        # only if tag is valid
        if re.match('[a-zA-Z0-9_]+', name):
            tags = self.usertags()
            if not name in tags:
                tags.append(name)
            self.jtags = json.dumps(tags)
            # IndicatorTag.objects.get_or_create(indicator=self,project=self.project,name=name)
        else:
            # invalid tag
            pass

    def deltag(self, name):
        tags = self.usertags()
        if name in tags:
            tags.remove(name)
        self.jtags = json.dumps(tags)

    def settags(self, tags):
        # add tags
        utags = self.usertags()
        for tag in tags:
            if not tag in utags:
                # add tag
                self.settag(tag)

        # delete tags
        for tag in utags:
            if not tag in tags:
                self.deltag(tag)

    def setdefargs(self):
        cas = CheckArg.objects.filter(cm=self.cm)
        args = dict()
        for ca1 in cas:
            args[ca1.argname] = ca1.default

        self.jcheckargs = json.dumps(args)

    #       do not set patience, because policy patience will be used
    #        if self.getarg('patience'): # if patience exists, set policy
    #            self.setarg('patience',self.policy.patience)

    # indicator.action
    # used from process
    def action(self):
        self.cm.action(self)

    #
    # update (and optionally create)
    # for PASSIVE indicators only!
    #

    def update_string(self, status, details=None, source=''):
        string = self.getarg('str')

        if not details:
            nndetails = status  # Not-None details
        else:
            nndetails = details

        if string == status:
            self.register_result('OK', nndetails, source=source)
            self.save()
            return self

        # only mismatch here!

        if (self.getopt('reinit') and not string):
            self.setarg('str', status)
            self.alert('initialize: {}'.format(shortstr(status)))
            self.register_result('OK', nndetails, source=source)
            self.save()
            return self

        if self.getopt('empty_err') and not status:
            if details:
                details = nndetails
            else:
                details = 'Error, because empty value'
            # self.status="ERR"
            self.register_result('ERR', details, source=source)
            self.save()
            return self

        if self.getopt('empty_ok') and not status:
            self.status = "OK"
            self.register_result('OK', nndetails, source=source)
            self.save()
            return self

        if self.getopt('dynamic'):
            reduction = string
            old_reduction = status

            if self.getopt('text'):
                diff = strdiff(string, status, sepstr="\n")
            else:
                diff = strdiff(string, status)

            if diff is not None:
                line = "Change: "
                for i in diff[0]:
                    line += '+' + i + ' '
                for i in diff[1]:
                    line += '-' + i + ' '
                self.log(line, typecode='update')
                self.alert(line, reduction=reduction, old_reduction=old_reduction)
            else:
                self.log('Change: old: {} new: {}'.format(
                    shortstr(json.dumps(string)), shortstr(json.dumps(status)[:30])),
                    typecode='update')
                self.alert('Change: old: {} new: {}'.format(
                    string,
                    status),
                    reduction=reduction, old_reduction=old_reduction)

            self.setarg('str', status)
            self.register_result('OK', nndetails, source=source)
            self.save()
            return self

        # static, string differs

        details = nndetails

        if self.getopt('text'):
            diff = strdiff(string, status, sepstr='\n')
        else:
            diff = strdiff(string, status)

        if diff is not None:
            line = "Change: "
            for i in diff[0]:
                line += '+' + i + ' '
            for i in diff[1]:
                line += '-' + i + ' '
            self.log(line)
            if self.status == "OK":
                self.alert(line)
        else:
            self.log('Mismatch: str: {} new: {}'.format(shortstr(json.dumps(string)), shortstr(json.dumps(status))),
                     typecode='update')
            if self.status == "OK":
                self.alert(
                    'Mismatch: str: {} new: {}'.format(shortstr(json.dumps(string)), shortstr(json.dumps(status))))

        self.register_result('ERR', nndetails, source=source)

        self.dead = False
        self.save()
        return self

    def update_numerical(self, status, details=None, source=''):

        def floatsuffix(s):
            if s.upper().endswith('K'):
                return float(s[:-1]) * 1024

            if s.upper().endswith('M'):
                return float(s[:-1]) * 1024 * 1024

            if s.upper().endswith('G'):
                return float(s[:-1]) * 1024 * 1024 * 1024

            return float(s)

        try:
            num = float(status)
        except ValueError:
            self.log("no update: status '{}' is not numerical.".format(status.encode('utf-8')),
                     typecode='indicator')
            return
        minlimstr = self.getarg('minlim', '')
        maxlimstr = self.getarg('maxlim', '')
        devup = self.getarg('diffmax', '')
        devdown = self.getarg('diffmin', '')
        current = self.getarg('current', '')

        if details is None:
            details = ""

        self.details = details

        if len(minlimstr):
            # minlim check
            try:
                minlim = floatsuffix(minlimstr)
            except ValueError:
                # problem indicator
                self.log("Bad minlim value '{}', cannot convert to float".format(minlimstr),
                         typecode='indicator')
                self.problem = True
                self.save()
                return

            if num < minlim:
                details += " | {} < {} (minlim)".format(num, minlim)

                self.log("{} < {} (minlim)".format(num, minlim),
                         typecode="update")
                # self.dead=False
                self.setarg('current', num)
                self.register_result('ERR', details, source=source)
                self.save()
                return

        if len(maxlimstr):
            # maxlim check
            try:
                maxlim = floatsuffix(maxlimstr)
            except ValueError:
                # problem indicator
                self.log("Bad maxlim value '{}', cannot convert to float".format(maxlimstr),
                         typecode="indicator")
                self.problem = True
                self.save()
                return

            if num > maxlim:
                details += " | {} > {} (maxlim)".format(num, maxlim)

                # self.status="ERR"
                self.log("{} > {} (maxlim)".format(num, maxlim),
                         typecode="update")
                # self.dead=False
                self.setarg('current', num)
                self.register_result('ERR', details, source=source)
                self.save()
                return

        # relative checks

        if len(current):
            curnum = float(current)
            devabs = num - curnum
            if curnum:
                devp = (num - curnum) * 100 / curnum
            else:
                devp = 0
            # print("num: {} curnum: {}, devabs: {} devp: {}".format(
            #   num,curnum,devabs,devp))

            if len(devup):
                if devup.endswith('%'):
                    try:
                        devuplimp = float(devup.rstrip('%'))
                        if devp > devuplimp:
                            details += " | {0:.2f}% > {1:.2f}% (diffmax)". \
                                format(devp, devuplimp)

                            self.log("{} < {} (devup %)".format(devp, devuplimp),
                                     typecode="update")
                            # self.dead=False
                            self.setarg('current', num)
                            self.register_result('ERR', details, source=source)
                            self.save()
                            return
                    except ValueError:
                        # problem indicator
                        self.log("Bad devup value '{}', cannot convert to float".format(devup),
                                 typecode="update")
                        self.problem = True
                        self.save()
                        return
                else:
                    # absolute value for devup
                    try:
                        devuplim = floatsuffix(devup)
                        if devabs > devuplim:
                            details += " | {} > {} (diffmax)". \
                                format(devabs, devuplim)

                            self.log("{} > {} (diffmax)".format(devabs, devuplim),
                                     typecode="update")
                            # self.dead=False
                            self.setarg('current', num)
                            self.register_result('ERR', details, source=source)
                            self.save()
                            return
                    except ValueError:
                        # problem indicator
                        self.log("Bad devup value '{}', cannot convert to float".format(devup),
                                 typecode="indicator")
                        self.problem = True
                        self.save()
                        return

            if len(devdown):
                if devdown.endswith('%'):
                    try:
                        devdownlimp = float(devdown.rstrip('%'))
                        if devp < devdownlimp:
                            details += " | {0:.2f}% < {1:.2f}% (diffmin)". \
                                format(devp, devdownlimp)

                            self.log("{} < {} (diffmin %)".format(devp, devdownlimp),
                                     typecode="update")
                            # self.dead=False
                            self.setarg('current', num)
                            self.register_result('ERR', details, source=source)
                            self.save()
                            return
                    except ValueError:
                        # problem indicator
                        self.log("Bad devdown value '{}', cannot convert to float".format(devdown),
                                 typecode="indicator")
                        self.problem = True
                        self.save()
                        return
                else:
                    # absolute value for devdown
                    try:
                        devdownlim = floatsuffix(devdown)
                        if devabs < devdownlim:
                            details += " | {} < {} (diffmin)". \
                                format(devabs, devdownlim)
                            # self.status="ERR"
                            self.log("{} < {} (diffmin)".format(devabs, devdownlim),
                                     typecode="update")
                            # self.dead=False
                            self.setarg('current', num)
                            self.register_result('ERR', details, source=source)
                            self.save()
                            return
                    except ValueError:
                        # problem indicator
                        self.log("Bad devdown value '{}', cannot convert to float".format(devdown),
                                 typecode="indicator")
                        self.problem = True
                        self.save()
                        return

        if details:
            details = details
        else:
            details = "{}".format(num)

        self.log("OK update {}".format(num),
                 typecode="update")
        self.setarg('current', num)
        self.register_result('OK', details, source=source)
        self.save()
        return self

    # indicator.create
    """
        return indicator or None, can raise ValueError
    """

    @staticmethod
    def create(project, idname, cmname='heartbeat', policy='Default', args=None, silent=None, limits=True):

        # checks first
        if not Indicator.validname(idname):
            raise ValueError('Bad name {}'.format(idname))

        # check unique name
        try:
            if project.get_indicator(idname):  # deleted=False by default
                raise ValueError('Project {} already has indicator {}'.format(project.get_textid(), idname))
        except Indicator.DoesNotExist:
            pass

        if limits and not project.owner.profile.can_new_indicator():
            #raise ValueError('User already hit maxinidicator limit ({}). Indicator not created'.format(
            #    project.owner.profile.getarg('maxindicators')))
            raise OkerrError('User already hit maxinidicator limit ({}). Indicator not created'.format(
                project.owner.profile.getarg('maxindicators')), 'LIMIT_MAXINDICATORS')

        if project.limited:
            raise ValueError('Project is limited. Indicator not created')

        i = Indicator()
        i.name = idname
        i.project = project
        i.ci = project.ci

        if silent:
            i.silent = True

        cm = CheckMethod.objects.filter(codename=cmname).first()
        if not cm:
            raise ValueError("ERROR! indicator.create has wrong cmname '{}'".format(cmname))
        i.cm = cm

        try:
            p = Policy.objects.get(project=project, name=policy)
        except ObjectDoesNotExist:
            log.error("ERROR! indicator.create has wrong policy '{}'".format(policy))
            return None
        i.policy = p

        i.save()
        project.log('created indicator {}'.format(i.name))
        set_rid(i)
        i.setdefargs()
        i.reschedule()

        # set defargs
        if args:
            for argname in args:
                i.setarg(argname, args[argname])

        i.save()
        return i

    #
    # return error string or None
    #
    #
    # error is None or error message
    #

    # indicator.update
    @staticmethod
    def update(project, idname, status="", details="", secret="", desc="",
               policy="Default", source=None, error=None, cmname=None, remoteip=None,
               tags=None, keypath=None, origkeypath=None):

        created = False

        allcm = CheckMethod.getCheckMethods()
        if tags is None:
            tags = list()

        "first, try to find proper indicator"

        if cmname is None:
            cmname = 'heartbeat'

        try:
            # print "try to find object with name '%s'" % idname
            i = project.get_indicator(idname)

        except ObjectDoesNotExist:

            # policy always specified, but can be Default or wrong
            try:
                p = Policy.objects.get(project=project, name=policy)
            except ObjectDoesNotExist:
                project.log("Cannot find policy '{}' to create indicator '{}', use default".format(policy, idname))
                p = Policy.objects.get(project=project, name='Default')

            if p.autocreate:
                if not Indicator.validname(idname):
                    return "Do not create indicator '{}': bad name".format(idname)

                pni = project.indicator_set.filter(deleted_at__isnull=True).count()
                maxni = project.owner.profile.getarg('maxindicators')

                if pni >= maxni:
                    raise OkerrError(
                        'Project already has {} indicators, maxindicators is {}. Indicator not created'
                            .format(pni, maxni),
                        'LIMIT_MAXINDICATORS')

                if p.secret:
                    if p.secret != secret:
                        # have secret, but no match
                        project.log("do not create \
                            indicator '{}' in policy '{}' because doesn't match \
                            secret".format(idname, p.name))
                        return "do not create indicator '%s' with policy '%s' because doesn't match secret" % (
                        idname, p.name)

                if project.limited:
                    return 'Project is limited. Indicator not created.'

                try:
                    cmarr = cmname.split('|')
                    cmdict = {}
                    codename = cmarr[0]
                    cmarr.pop(0)

                    for e in cmarr:
                        (k, v) = e.split('=')
                        cmdict[k.strip()] = v.strip()
                except ValueError:
                    log.info('Bad cm line: \'{}\' project: {}, i: {} source: {} ip: {} '. \
                             format(cmname, project.name, idname, source, remoteip))
                    return 'bad cm line\'{}\''.format(cmname)

                if not codename in allcm:
                    return "Unknown checkname with codename '{}'".format(codename)

                cm = CheckMethod.objects.filter(codename=codename).first()
                if not cm:
                    log.warning("Cannot get {} method!".format(codename))
                    return "No such method '{}'".format(codename)

                if not cm.enabled:
                    log.warning("Method '{}' is disabled".format(codename))
                    return "Method '{}' is disabled".format(codename)

                # create new indicator
                i = Indicator(project=project, name=idname, policy=p, cm=cm, desc=desc)
                i.ci = project.ci
                created = True

                i.reschedule()
                i.save()
                Indicator.update_tproc_sleep()

                # set_rid(i)
                i.setdefargs()
                i.setarg('secret', '')  # set empty secret
                for tag in tags:
                    i.settag(tag)

                # for argname,argvalue in zip(methargs[codename], cmarr):
                #    i.log('create arg {} = {}'.format(argname,argvalue))
                #    i.setarg(argname,argvalue)
                for argname, arg in allcm[codename]['args'].items():
                    # check if it exists in update and if yes - override
                    if argname in cmdict:
                        i.log('Create arg {} = {}'.format(
                            argname, cmdict[argname]),
                            typecode="indicator")
                        i.setarg(argname, cmdict[argname])
                    else:
                        # not specified, use default
                        i.setarg(argname, arg['default'])

                i.save()
                i.alert('autocreated from {}'.format(remoteip))

                if i.cm.active():
                    # this is active indicator, we create it, but no need to update it
                    return None
            else:
                project.log("Cannot create indicator {} because policy {} has autocreate off".format(idname, p.name))
                return "Cannot create indicator %s because policy %s has autocreate off" % (idname, p.name)

        # now we have indicator (old, or created it)

        # check if wrong ci and warn
        if i.ci != myci() and not i.name.startswith('bench:'):
            log.warning(
                "bad ci update i#{}: {} / {} i.ci: {} myci: {}".format(i.id, i.project.get_textid(), i.name, i.ci,
                                                                        myci()))

        # check if this update method is allowed
        if source is not None:
            fieldname = source + 'update'
            if not getattr(i.policy, fieldname):
                line = "src:'{}' updates are not allowed".format(source)
                i.log(line, typecode="indicator")
                return line

        # check if this ip is allowed
        if remoteip:
            if not i.policy.checkip(remoteip):
                line = "updates from {} not allowed".format(remoteip)
                i.log(line, typecode="indicator")
                return line

        if not i.cm.codename in ['heartbeat', 'numerical', 'string']:
            # return 'Bad method'
            raise OkerrError('Indicator exists with cm: {}'.format(i.cm.codename), code='BAD_METHOD')

        # get secret
        isecret = i.getarg('secret', '')

        # if not protected by personal secret, protect by policy secret
        if not isecret:
            isecret = i.policy.secret

        if isecret:
            if not secret:
                i.log("do not update, because secret required but not specified")
                return "Require secret"
            if isecret != secret:
                # have secret, but no match
                i.log("do not update status, because secret does not match")
                return "Bad secret"

        # probably ok. log all update details
        src_line = "{}:{}".format(source, remoteip)

        #        line = "{} update from IP {}"\
        #            .format(source,remoteip)
        #        i.log(line, typecode="update")

        # now, cm-specific handling
        if i.cm.codename == 'heartbeat':
            # fix status
            status = status.upper()
            if status in ['OK', 'ERR']:
                i.register_result(status, details, source=src_line)
                i.save()
            else:
                log.info('Refuse update heartbeat {} bad status {}'.format(i.name, repr(status)))
        elif i.cm.codename == 'numerical':
            i.update_numerical(status, details, source=src_line)
        elif i.cm.codename == 'string':
            i.update_string(status, details, source=src_line)
        else:
            print("unsupported update for cmcodename {}".format(i.cm.codename))

        if error is not None:
            # error
            i.log('Problem: {}'.format(error), typecode="indicator")
            i.problem = True

        # changerec=IChange(indicator=i, oldstate=i._status, newstate=i._status)
        # changerec.save()

        i.keypath = keypath
        i.origkeypath = origkeypath

        # i.touch()
        # i.reschedule()
        i.save()

        # return i
        return None


class Profile(TransModel):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    # lastlogin = models.DateTimeField(null=True)       // in user model
    # created = models.DateTimeField(auto_now_add=True)

    sendalert = models.BooleanField(default=True)
    sendsummary = models.BooleanField(default=True)
    nextsummary = models.DateTimeField(null=False, default=timezone.now)
    sumtime = models.IntegerField(default=0)
    mtime = models.DateTimeField(auto_now=True)

    patrolled = models.DateTimeField(auto_now_add=True)

    telegram_name = models.CharField(max_length=100, default='', null=True)
    telegram_chat_id = models.BigIntegerField(default=None, null=True)  # e.g. '113387111' bigint!!

    # sha1 hash of last seen motd
    last_motd = models.CharField(max_length=100, default=None, null=True)

    training_stage = models.CharField(max_length=100, default=None,
                                      null=True)  # current tstage (not completed). None == first stage

    partner_name = models.CharField(max_length=100, default=None, null=True)  # e.g. 'example.com'
    partner_id = models.CharField(max_length=100, default=None,
                                  null=True)  # e.g. '00220' id of user in partner. e.g. contract no or email or anything
    jargs = models.TextField(default='{}')  # any other arguments in JSON format

    # profile.set_ci
    def set_ci(self, ci, force=False):
        """ set cluster index """
        if self.ci == ci and not force:
            return

        print("Profile {} set to ci {}".format(self, ci))
        self.ci = ci
        for p in self.user.project_set.all():
            p.set_ci(ci, force)
            p.tsave()

    # profile.set_delete
    def set_delete(self):
        # set_delete for projects
        for p in self.user.project_set.all():
            p.set_delete()
            p.save()
        # call parent
        return super(Profile, self).set_delete()

    # profile.predelete
    def predelete(self):
        for project in self.user.project_set.all():
            project.predelete()
            project.delete()
        self.user.delete()

    # profile.fix
    def fix(self, verbose=False):
        fixed = False
        if self.user.date_joined is None:
            print("fix date_joined for", self)
            self.user.date_joined = timezone.now()
        return fixed

    # profile fix_static
    @staticmethod
    def fix_static(verbose, save):
        User = get_user_model()
        for user in User.objects.filter(profile__isnull=True):
            print("user: {} (email: {}) has no profile".format(user, user.email))

    # profile.calculate_ci
    def calculate_ci(self):

        csum = zlib.crc32(self.rid)  # checksum
        csz = len(settings.MACHINES)
        return csum % csz

    # profile.init
    def init(self, partner_access=False, textid=None):
        now = timezone.now()
        self.sumtime = (now - now.replace(hour=0, minute=0, second=0,
                                          microsecond=0)).total_seconds()

        self.schedulenext()

        # create project for myself
        # project = Project(name=self.user.username, owner=self.user)
        self.ci = myci()

        Project.create(self.user.username, self.user, partner_access=partner_access, textid=textid)

    # profile.inits
    def inits(self, partner_access=False, textid=None):
        self.init(partner_access=partner_access, textid=textid)
        # print "inits after init, now save. textid:",self.textid
        self.save()

    # profile.touch
    def touch(self, touchall=False):

        set_rid(self)
        self.mtime = timezone.now()

        # te = TransactionEngine()
        # te.update_instance(self)

        if touchall:
            self.save()

    # profile.tsave()
    def tsave(self):
        uni_tsave(self)

    # true is user accepted last version of EULA
    def eula_accepted(self):
        eulaver = int(SystemVariable.get('eulaver', -1))
        accepted = self.getmaxval('eulaver_accepted')

        # log.info('accepted? eulaver: {} accepted: {}'.\
        #    format(eulaver,accepted))

        if accepted and accepted >= eulaver:
            return True
        else:
            return False

    def schedulenext(self):
        # always schedule to prev. scheduled + N day(s)
        # while scheduled in past
        now = timezone.now()
        while self.nextsummary <= now:
            self.nextsummary = self.nextsummary + datetime.timedelta(days=1)

    def sumtimehhmm(self):
        hh = int(self.sumtime / 3600)
        mm = int((self.sumtime - (hh * 3600)) / 60)
        hhmm = "%02d:%02d" % (hh, mm)
        return hhmm

    # profile.groups
    def groups(self):
        g = {}
        for m in Membership.objects.filter(profile=self):
            g[m.groupname] = m.expires
        return g

    # profile.select_best_group - return most 'expensive' group
    def get_best_membership(self):
        mm = None

        for m in self.membership_set.all():
            if m.groupname.startswith('perk:'):
                continue
            if mm is None or m.get_weight() > mm.get_weight():
                # new candidate!
                mm = m

            return mm


    # profile.groupstext (only groups, not perks)
    def groupstext(self):
        g = list()
        for m in self.membership_set.exclude(groupname__startswith='perk'):
            d = dict()
            d['name'] = m.groupname
            if m.expires:
                d['expires'] = shortdate(m.expires)
                d['left'] = dhms(m.expires - timezone.now())
            else:
                d['expires'] = None
                d['left'] = None
            g.append(d)
        return g

    # profile.perkstext (perks, not groups)
    def perkstext(self):
        g = list()
        for m in self.membership_set.filter(groupname__startswith='perk'):
            d = dict()
            d['name'] = m.groupname
            if m.expires:
                d['expires'] = shortdate(m.expires)
                d['left'] = dhms(m.expires - timezone.now())
            else:
                d['expires'] = shortdate(m.expires)
                d['left'] = dhms(m.expires - timezone.now())
            g.append(d)
        return g

    # profile.projects
    # returns list of all projects
    def projects(self):
        t = []
        for tm in ProjectMember.objects.filter(email=self.user.email):
            t.append(tm.project)
        return t

    def projects_tuples(self):
        t = []
        for tm in ProjectMember.objects.filter(email=self.user.email):
            t.append((tm.project.id, tm.project.get_textid(), tm.project.name))
        return t

    def live_projects(self):
        out = list()
        for tm in ProjectMember.objects.filter(email=self.user.email, project__deleted_at__isnull=True):
            out.append(tm.project)
        out.sort(key=lambda x: x.name, reverse=False)
        return out

    # profile.ownerprojects
    def ownerprojects(self):
        return self.user.project_set.all()
        # Project.objects.filter(owner=self.user)

    # returns list of all projects WHERE user is tadmin
    def aprojects(self):
        t = []
        for tm in ProjectMember.objects.filter(user=self.user, tadmin=True):
            t.append(tm.project)
        return t

    def iprojects(self):
        t = []
        for tm in ProjectMember.objects.filter(user=self.user, iadmin=True):
            t.append(tm.project)
        return t

    # list of project where user is owner
    def oprojects(self):
        t = []
        return Project.objects.filter(owner=self.user)
        for p in Project.objects.filter(owner=self.user):
            t.append(p)
        return t

    # profile.wipe
    def wipe(self):
        Membership.objects.filter(profile=self).delete()
        ProfileArg.objects.filter(profile=self).delete()

    def dumpgroupinfo(self):
        print("dump group info for {}".format(self.user.username))

        for m in Membership.objects.filter(profile=self):
            print(m)

        for pa in ProfileArg.objects.filter(profile=self):
            print(pa)

    # profile.groupargs
    def groupargs(self):
        args = {}
        args['maxindicators'] = self.getarg('maxindicators')
        args['teamsize'] = self.getarg('teamsize')
        args['minperiod'] = self.getarg('minperiod')
        args['maxprojects'] = self.getarg('maxprojects')
        args['maxstatus'] = self.getarg('maxstatus')
        args['settextname'] = self.getarg('settextname', 0)
        args['login'] = self.getarg('login')
        # args['qi'] = self.get_qindicators()

        return args

    def dec(self, name):
        # if var name is higher then zero, return current value and decrease
        pa = ProfileArg.objects.filter(profile=self, name=name).first()
        if not pa:
            print("no such variable {} for this profile".format(name))
            return
        if pa.value > 0:
            oldval = pa.value
            pa.value = pa.value - 1
            pa.save()
            return oldval

    @classmethod
    # profile.patrol
    def patrol(cls, period=None):

        if period is None:
            patrol_period = datetime.timedelta(hours=1)
        else:
            patrol_period = period

        # patrol_period = datetime.timedelta(seconds=1)

        # throttle it

        def getminqi(qi, period):
            klist = qi.keys()
            # filter too large perks
            klist = filter(lambda x: x <= period, klist)
            return max(klist)


        for profile in cls.objects.filter(ci=myci(), patrolled__lt=timezone.now() - patrol_period):
            log.info("patrol profile {}".format(profile))
            report = dict()

            na = profile.get_na_indicators()
            maxi = profile.getarg('maxindicators')

            # maxindicators
            if na > maxi:
                for i in Indicator.objects.filter(project__in=profile.ownerprojects(), disabled=False).order_by(
                        'created')[profile.get_maxindicators():]:
                    i.log('[PATROL] disabled, because enabled {} or {} maximum'.format(na, maxi))
                    log.info('[PATROL] disabled indicator {}, because enabled {}/{}'.format(i.get_fullname(), na, maxi))
                    i.disable()
                    i.save()
                    # add to report
                    if not 'maxindicators' in report:
                        report['maxindicators'] = list()
                    report['maxindicators'].append(i)

            # qindicators
            base_minperiod = profile.getarg('minperiod', strict=True)
            qi = profile.get_qindicators()

            if base_minperiod:
                # only for non-none. just in case

                for i in Indicator.objects.filter(project__in=profile.ownerprojects(), disabled=False):
                    if i.policy.get_period() >= base_minperiod:
                        # regular indicator, not quick. not interested, skip it
                        continue

                    try:
                        plimit = getminqi(qi, i.policy.get_period())
                    except ValueError:
                        i.log(
                            '[PATROL] inidicator disabled, because no available minperiod perks left (max: {})'.format(
                                maxi))
                        log.info(
                            '[PATROL] indicator disabled {}, because no available minperiod perks left (max: {})'.format(
                                i.get_fullname(), maxi))
                        i.disable()
                        i.save()
                        # add to report
                        if not 'minperiod' in report:
                            report['minperiod'] = list()
                        report['minperiod'].append(i)

                    else:
                        if plimit in qi:
                            qi[plimit] -= 1
                            if qi[plimit] == 0:
                                del qi[plimit]

            # teamsize
            maxts = profile.getarg('teamsize')
            for p in profile.user.project_set.filter(limited=False).all():
                ts = p.nmembers()
                if ts > maxts:
                    log.info(
                        "[PATROL] limit project {} owner {} teamsize {}/{}".format(p.get_textid(), p.owner.username, ts,
                                                                                   maxts))
                    p.limited = True
                    p.save()
                    if not 'teamsize' in report:
                        report['teamsize'] = list()
                    report['teamsize'].append(p)

            # projects
            nprojects = profile.user.project_set.filter(limited=False).count()
            maxprojects = profile.getarg('maxprojects')

            if nprojects > maxprojects:
                lp = nprojects - maxprojects
                for p in profile.user.project_set.filter(limited=False).order_by('-created')[:lp]:
                    log.info("[PATROL] limit project {} owner {} num {}/{}".format(p.get_textid(), p.owner.username,
                                                                                   nprojects, maxprojects))
                    p.limited = True
                    p.save()
                    if not 'maxprojects' in report:
                        report['maxprojects'] = list()
                    report['maxprojects'].append(p)

            # unlimit projects
            # unlimit only if:
            #   -  good teamsize
            #   -  good maxprojects

            nprojects = profile.user.project_set.filter(limited=False).count()
            maxprojects = profile.getarg('maxprojects')

            can_unlimit = maxprojects - nprojects
            if can_unlimit > 0:
                for p in profile.user.project_set.filter(limited=True):
                    if p.nmembers() <= profile.getarg('teamsize'):
                        # unlimit it
                        log.info("[PATROL] UNlimit project {} owner {} np:{}/{} ts: {}/{}".format(
                            p.get_textid(), p.owner.username, nprojects, maxprojects, p.nmembers(),
                            profile.getarg('teamsize')))
                        p.limited = False
                        p.save()
                        can_unlimit -= 1
                        if 'unlimited' not in report:
                            report['unlimited'] = list()
                        report['unlimited'].append(p)

                    if can_unlimit == 0:
                        break

            # report if changes are done
            if report:
                from_email = settings.FROM
                # plaintext = get_template('patrol-report.txt')
                htmly = get_template('patrol-report.html')

                subject = 'okerr IMPORTANT alert (patrol report)'

                report['siteurl'] = settings.SITEURL.strip('/')
                report['hostname'] = settings.HOSTNAME
                report['profile'] = profile

                report['hostname'] = settings.HOSTNAME,
                report['MYMAIL_FOOTER'] = settings.MYMAIL_FOOTER

                # text_content = plaintext.render(d)
                html_content = htmly.render(report)

                send_email(profile.user.email, subject=subject, html=html_content, what="patrol report")

            profile.patrolled = timezone.now()
            profile.save()

    @classmethod
    # profile.cron
    def cron(cls):
        cls.patrol()

    # profile.can_login
    def can_login(self):
        try:
            return self.getarg('login') == 1
        except KeyError as e:
            log.error('can_login exception: {}'.format(e))
            return False

    # profile.get_jarg
    def get_jarg(self, key):
        jargs = json.loads(self.jargs or '{}')
        return jargs[key]

    # profile.set_jarg
    def set_jarg(self, key, value):
        jargs = json.loads(self.jargs or '{}')
        jargs[key] = value
        self.jargs = json.dumps(jargs)

    # specific jargs getters
    def get_jarg_full_interface(self):
        try:
            return self.get_jarg('full_interface')
        except KeyError:
            return False

    #
    # FIXME: wipe ProfileArg, use values from code?
    #

    # profile.getmaxval
    def getmaxval(self, name, default=None):
        maxval = default
        for pa in ProfileArg.objects.filter(profile=self, name=name):
            if maxval is None:
                maxval = pa.value
            elif pa.value > maxval:
                maxval = pa.value
        return maxval

    def getminval(self, name, default=None):
        minval = default
        for pa in ProfileArg.objects.filter(profile=self, name=name):
            if minval is None:
                minval = pa.value
            elif pa.value < minval:
                minval = pa.value
        return minval

    def getsumval(self, name):
        s = self.profilearg_set.filter(name=name).aggregate(Sum('value'))['value__sum']
        if s is None:
            return 0
        return s

    # profile.find
    @staticmethod
    def find_user(uname):
        """ return user. uname is either email or partner_name:partner_id """

        User = get_user_model()
        user = User.objects.filter(email=uname).first()
        if user:
            # find by email
            return user
        try:
            p_name, p_id = uname.split(':')
        except ValueError:
            return None

        if p_name and p_id:
            p = Profile.objects.filter(partner_name=p_name, partner_id=p_id).first()
            if p:
                return p.user
        return None

    """
        force this acc to sync with all other servers
    """

    def force_sync(self):
        rs = RemoteServer(name=settings.HOSTNAME)

        if rs.is_net():
            for rrs in rs.all_other():
                log.info('force sync profile {} to {}'.format(self.user.username, rrs))
                rrs.force_sync(self.user.username)
        else:
            log.info('skip sync all, because myself not networked')

    # profile.assign
    def assign(self, group=None, time=None, add=False, force_assign=False):

        assert(isinstance(group, str))

        #
        #
        # if 'add':
        #    add more time to membership in group
        # else
        #    make user to be member of group for for this time from now
        # group can be group or group name
        #
        # if force_assign - user will be assigned to group even 2nd time

        #if isinstance(group, str):
        #    # groupname => group
        #    group = Group.objects.filter(name=group).get()

        if isinstance(time, int):
            time = datetime.timedelta(seconds=time)

        m = Membership.objects.filter(groupname=group, profile=self).first()

        if m and not force_assign:
            # renew
            # log.info("user {} is already member of group {}".format(self.user.username, group))

            if m.expires is None:
                # no need to renew, just refill
                # m.refilled = timezone.now()
                # group.fill(self, m.expires)
                m.save()
                return


            # expiration limited
            if add:
                exptime = max(m.expires, timezone.now()) + time
            else:
                exptime = max(m.expires, timezone.now() + time)

            m.expires = exptime

            # m.refilled = timezone.now()
            # group.fill(self, m.expires)

            m.save()
            return

        # new group for user
        if time is None:
            exptime = None
        else:
            exptime = timezone.now() + time

        log.info("Assign user {user} to group {group} until {exptime}".format(
            user=self.user.username,
            group=group, exptime=exptime))

        m = Membership(groupname=group, profile=self, expires=exptime, granted=timezone.now())
        # group.fill(self, exptime)
        # m.refilled = timezone.now()
        m.save()

    # profile.alerts
    def alerts(self):
        return self.user.alertrecord_set.all()

    # profile.mail_alerts
    def mail_alerts(self):
        now = timezone.now()
        return self.user.alertrecord_set.filter(proto='mail', release_time__lte=now)

    def __str__(self):
        if not hasattr(self, 'user'):
            uname = "user not set"
        elif not self.user.username:
            uname = "username not set"
        else:
            uname = self.user.username

        return "Profile for user {}".format(uname)

    # profile.dump
    def dump(self):

        if self.deleted_at:
            del_suffix = '[DELETED {}]'.format(self.deleted_at)
        else:
            del_suffix = ''
        print("Profile: {} {}".format(self.user.username, del_suffix))
        print("ci:", self.ci)
        print("partner: {} : {}".format(self.partner_name, self.partner_id))
        bindings = list()
        for b in Oauth2Binding.objects.filter(profile=self):
            bindings.append(b.provider)
        if bindings:
            print("OAuth:", ' '.join(bindings))

        print("telegram: {} ({})".format(self.telegram_name, self.telegram_chat_id))
        print("traning stage: {}".format(repr(self.training_stage)))
        print("sendalert:", self.sendalert)
        print("sendsummary:", self.sendsummary)
        if self.nextsummary > timezone.now():
            print("nextsummary: {} ({})".format(self.nextsummary, chopms(self.nextsummary - timezone.now())))
        else:
            print("nextsummary: {} (now)".format(self.nextsummary))

        print("Profile args:")
        for pa in self.profilearg_set.all():
            print(pa)

        print("owner:")
        for p in self.user.project_set.all():
            print("  '{}' {}".format(p, ' '.join(p.get_textids())))

        print("member:")
        for pm in ProjectMember.objects.filter(email=self.user.email).all():
            p = pm.project
            print("  '{}' {}".format(p, ' '.join(p.get_textids())))

        print()

    @staticmethod
    # profile.syncrestore
    def syncrestore(pd, sync):
        User = get_user_model()
        rid = pd['rid']
        print("Profile restore {} {}".format(rid, pd['email']))

        try:
            p = Profile.objects.get(rid=rid)
        except ObjectDoesNotExist:
            print("No such profile, create")
            user = User.objects.create_user(pd['email'], pd['email'])
            user.password = pd['password']
            user.save()
            print("created user, id:", user.id)
            # user.save()
            p = Profile(user=user)
            p = sync.restore_helper(p, pd)
            p.save()

    # profile.syncbackup
    def syncbackup(self, sync, tstamp):

        # print sync.relations(self.user)
        backup = sync.backup_helper(self, None)

        """ save data from user model """
        backup['email'] = self.user.email
        backup['password'] = self.user.password

        """ save data from other models """
        # backup['Project'] = list()
        # for p in self.user.project_set.filter(mtime__gte = tstamp):
        #    backup['Project'].append(p.syncbackup(sync,tstamp))

        return backup

    # profile.transaction_dump
    def transaction_postdump(self, d):
        # print "profile.transaction_postdump(self,{})".format(d)
        for f in ['email', 'password', 'first_name', 'last_name']:
            d[f] = getattr(self.user, f, None)

    # profile.post_export
    def post_export(self, d):
        for f in ['email', 'password', 'first_name', 'last_name', 'last_login', 'date_joined']:
            value = getattr(self.user, f, None)
            ff = self.user._meta.get_field(f)
            if isinstance(ff, models.fields.DateTimeField):
                value = dt2unixtime(value)
            d[f] = value

    # profile.transaction_postload
    def transaction_postload(self, d):
        super(Profile, self).transaction_postload(d)

        User = get_user_model()
        rid = self.rid
        createdstr = ""

        if self.user_id is None:
            user = User.objects.create_user(d['email'], d['email'])
            user.save()
            self.user = user
            createdstr = " (created)"
        else:
            user = self.user

        for f in ['email', 'password', 'first_name', 'last_name', 'last_login', 'date_joined']:
            if f in d:
                value = d[f]
                ff = user._meta.get_field(f)
                if isinstance(ff, models.fields.DateTimeField):
                    value = unixtime2dt(value)
                setattr(self.user, f, value)
        user.save()
        # print "Profile postloaded {} {}{}".format(rid, self,createdstr)

    # project.get_na_indicators()
    # return number of non-disabled indicators for this user
    def get_na_indicators(self):
        na = 0
        for p in self.ownerprojects():
            na += p.get_na_indicators()
        return na

    def can_new_indicator(self):
        i = self.get_na_indicators()
        maxi = self.getarg('maxindicators')

        if i >= maxi:
            return False
        return True

    def get_qindicators(self):
        qi = dict()

        for m in self.membership_set.all():

            r = m.get_static_arg_prefix("minperiod:", None)
            if r is None:
                continue
            argname, value = r

            try:
                period = int(argname.split(':')[1])
            except ValueError as e:
                print("cannot get qindicators self: {} argname: {}".format(self, argname))
                raise

            if not period in qi:
                qi[period] = 0
            qi[period] += value
        return qi

    # get_ methods are wrappers for getarg. needed to call it from template
    def get_minperiod(self):
        return self.getarg('minperiod', strict=True)

    def get_maxindicators(self):
        return self.getarg('maxindicators')

    def get_maxstatus(self):
        return self.getarg('maxstatus')

    def get_maxdyndns(self):
        return self.getarg('maxdyndns')

    def get_teamsize(self):
        return self.getarg('teamsize')

    def get_maxprojects(self):
        return self.getarg('maxprojects')

    """
        profile.get_emembership
        get effective membership (only one top-level plan)
    """

    def get_emembership(self):
        mm = None

        for m in self.membership_set.all():
            if m.groupname.startswith('perk:'):
                yield m
            elif mm is None or mm.get_weight() < m.get_weight():
                mm = m

        if mm:
            # print "yield maingroup", mm
            yield mm

    # profile.getarg
    def getarg(self, name, strict=False):

        argtypes = {
            'maxindicators': {
                'type': sum,
                'default': 0
            },
            'maxstatus': {
                'type': sum,
                'default': 0
            },
            'maxdyndns': {
                'type': sum,
                'default': 0
            },
            'status_maxsubscribers': {
                'type': sum,
                'default': 0
            },
            'settextname': {
                'type': max,
                'default': 0
            },
            'mintextidlen': {
                'type': min,
                'default': 6
            },
            'minperiod': {
                'type': min,
                'default': 3600,
                'suffix': 1
            },
            'teamsize': {
                'type': sum,
                'default': 1
            },
            'maxprojects': {
                'type': sum,
                'default': 1,
            },
            'login': {
                'type': max,
                'default': 0
            }
        }

        control = argtypes[name]

        values = list()
        for m in self.get_emembership():
            values.append(m.get_static_arg(name, None))
            if 'suffix' in control and not strict:
                t = m.get_static_arg_prefix(name + ':', None)
                if t is not None:
                    try:
                        values.append(int(t[0].split(':')[1]))
                    except ValueError as e:
                        print("getarg failed. self: {} name: {}, t: {}".format(self, name, t))
                        raise
        # filter out Nones
        values = list(filter(lambda x: x is not None, values))

        if not values:
            values = [control['default']]

        return control['type'](values)

    # profile.reanimate
    def reanimate(self):
        for p in self.user.project_set.all():
            p.reanimate()

    # profile.post_import
    def post_import(self, d):
        self.transaction_postload(d)
        self.save()


class LogRecord(models.Model):
    # user = models.ForeignKey(settings.AUTH_USER_MODEL)
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    indicator = models.ForeignKey(Indicator, on_delete=models.CASCADE, null=True)
    deadname = models.CharField(max_length=200, null=True)  # dead indicator name, can not be indicator FK
    typecode = models.IntegerField(default=1, db_index=True)  # 1 is update record. Default for migration
    message = models.CharField(max_length=10000)
    created = models.DateTimeField(auto_now_add=True, db_index=True)

    typecodes = ['unspecified', 'update', 'indicator', 'other', 'alert', 'project', 'dyndns']

    @staticmethod
    def get_typecode(code):
        try:
            return LogRecord.typecodes.index(code)
        except ValueError:
            return 0

    def __str__(self):
        timestr = self.created.strftime("%d/%m/%Y %H:%M:%S")
        # if self.indicator:
        #    return "%s %s: %s" % (timestr, self.indicator.name, self.message)
        # else:
        return "%s %s" % (timestr, self.message)

    # logrecord.cron
    @staticmethod
    def cron():
        # delete old records
        now = timezone.now()

        update_code = LogRecord.get_typecode('update')

        # delete update logrecords
        old = now - settings.LOGRECORD_UPDATE_AGE
        LogRecord.objects.filter(created__lt=old, typecode=update_code).delete()

        # delete all the rest (longer period)
        old = now - settings.LOGRECORD_AGE
        LogRecord.objects.filter(created__lt=old).delete()


class AlertRecord(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    indicator = models.ForeignKey(Indicator, on_delete=models.CASCADE, null=True)
    message = models.CharField(max_length=10000)
    proto = models.CharField(max_length=100, default='mail')
    created = models.DateTimeField(auto_now_add=True)
    release_time = models.DateTimeField(default=timezone.now)
    reduction = models.CharField(max_length=200, null=True)

    def __str__(self):
        timestr = self.created.strftime("%d/%m/%Y %H:%M:%S")
        if self.indicator:
            return "%s (%s) %s %s: %s" % (timestr, self.proto, self.user.username, self.indicator.name, self.message)
        else:
            return "%s (%s) %s %s" % (timestr, self.proto, self.user.username, self.message)


class Group(models.Model):
    name = models.CharField(max_length=200)
    refillperiod = models.IntegerField(default=30 * 86400)

    @staticmethod
    def get_groups(name=None):
        # https://ru.wikipedia.org/wiki/%D0%A1%D0%BF%D0%B8%D1%81%D0%BE%D0%BA_%D0%BD%D0%B0%D0%B7%D0%B2%D0%B0%D0%BD%D0%B8%D0%B9_%D0%B7%D0%B2%D1%91%D0%B7%D0%B4
        # Список названий звезд

        if name is None:
            return settings.PLANS
        return settings.PLANS[name]

    @staticmethod
    def UNUSEDQ_reinit_groups(delete=False, readonly=False, quiet=False):

        goodargs = ['maxindicators', 'settextname', 'mintextidlen', 'minperiod', 'teamsize', 'maxprojects', 'maxstatus',
                    'login', 'maxdyndns', 'status_maxsubscribers',
                    'add_maxindicators', 'add_teamsize', 'add_maxprojects', 'minperiod:1', 'minperiod:60',
                    '_price', '_autorenew', '_weight']

        gconf = Group.get_groups()

        if readonly:
            # readonly means no delete
            delete = False

        for gname, args in gconf.items():
            if not quiet:
                print("group {}".format(gname))
            try:
                g = Group.objects.get(name=gname)
            except ObjectDoesNotExist:
                if not quiet:
                    print("Group {} Not found. Create".format(gname))
                if not readonly:
                    g = Group.objects.create(name=gname)
                    g.save()
                else:
                    print("readonly. not created")

            for argname in args:

                if not argname in goodargs and not argname.startswith('minperiod:'):
                    print("WARN: {}: {} not in goodargs".format(gname, argname))

                try:
                    ga = g.grouparg_set.get(name=argname)

                    if ga.value != args[argname]:
                        print("fix argument {}:{} = {} -> {}".format(gname, argname, ga.value, args[argname]))
                        if not readonly:
                            ga.value = args[argname]
                            ga.save()
                        else:
                            print("readonly, not fix")

                except ObjectDoesNotExist:
                    if not quiet:
                        print("create argument {}:{} = {}".format(gname, argname, args[argname]))
                    if not readonly:
                        ga = g.grouparg_set.create(name=argname, value=args[argname])
                        ga.save()
                    else:
                        print("readonly. not create")

            for ga in g.grouparg_set.all():
                if not ga.name in args:
                    if delete:
                        print("delete arg {}".format(ga))
                        ga.delete()
                    else:
                        print("NOT delete arg {}".format(ga))

        for g in Group.objects.all():
            if g.name not in gconf:
                if delete:
                    print("delete group:", g)
                    g.delete()
                else:
                    print("NOT delete group:", g)

        pass

    @staticmethod
    def group_names():
        gconf = Group.get_groups()
        for name in gconf.keys():
            if not name.startswith('perk:'):
                yield name

    @staticmethod
    def perk_names():
        gconf = Group.get_groups()
        for name in gconf.keys():
            if name.startswith('perk:'):
                yield name

    @staticmethod
    def get_calculated():
        gconf = Group.get_groups()

        def get_checks(period, time=3600 * 24 * 30):
            return time / period

        for gname, gdata in gconf.items():

            print("+", gname)

            gdata['_quick_checks'] = 0
            gdata['_base_maxindicators'] = 0
            gdata['_base_checks'] = 0

            maxi_base = 0

            if 'minperiod' in gdata and 'maxindicators' in gdata:
                # calculate _checks
                maxi_base = gdata['maxindicators']

            for k in gdata.keys():
                if k.startswith('minperiod:'):
                    maxi_base -= gdata[k]
                    qperiod = int(k.split(':')[1])
                    gdata['_quick_checks'] += gdata[k] * get_checks(qperiod)

            gdata['_base_maxindicators'] = maxi_base

            if 'minperiod' in gdata:
                gdata['_base_checks'] = maxi_base * get_checks(gdata['minperiod'])

            print(gname)
            print('---')
            print(json.dumps(gdata, indent=4))
            print()

            if '_price' in gdata and 'maxindicators' in gdata:
                gdata['_price_1indicator'] = round(float(gdata['_price']) / gdata['maxindicators'], 3)
                gdata['_price_1check'] = round(
                    100 * float(gdata['_price']) / (gdata['_quick_checks'] + gdata['_base_checks']), 3)

        return gconf

    # group.get_static_arg
    def UNUSED_get_static_arg(self, argname, default=None):
        gconf = Group.get_groups(self.name)
        if argname in gconf:
            return gconf[argname]
        return default

    # group.get_static_arg_prefix
    def UNUSED_get_static_arg_prefix(self, argprefix, default=None):
        gconf = Group.get_groups(self.name)
        for argname in gconf:
            if argname.startswith(argprefix):
                return (argname, gconf[argname])
        return None

    def UNUSED_get_weight(self):
        w = self.get_static_arg('_weight')
        if w:
            return w

        w = self.get_static_arg('_price')
        if w:
            return w

        return 1

    # group.fill
    def UNUSED_fill(self, profile, expires):
        # self.refill(profile,expires)
        pass

    # group.refill
    def UNUSED_refill(self, profile, expires):
        counters = []  # ['numalerts']
        log.info("refill {name} for user {user}".format(name=self.name, user=profile.user.username))
        # !!! update if available, not create
        for ga in GroupArg.objects.filter(group=self):

            if ga.name not in counters:
                # const name, set higher expires for same value or create new
                pa = ProfileArg.objects.filter(profile=profile, name=ga.name, value=ga.value, group=self).first()
                if pa:
                    if pa.expires is not None:
                        if expires is None:
                            if pa.expires is not None:
                                # extend argument to forever
                                pa.expires = None
                        elif pa.expires < expires:  #
                            pa.expires = expires
                    else:
                        # pa.expires is None, no need to refill it
                        pass
                else:
                    pa = ProfileArg(profile=profile, name=ga.name, value=ga.value, expires=expires, group=self)
                pa.save()
            else:
                # counter (like numalers limit). refill if exists, or create new
                pa = ProfileArg.objects.filter(profile=profile, name=ga.name, group=self).first()
                if pa:
                    # refill
                    if pa.value < ga.value:
                        pa.value = ga.value

                    if pa.expires is not None:
                        if expires is None:
                            if pa.expires is not None:
                                # extend argument to forever
                                pa.expires = None
                        elif pa.expires < expires:  #
                            pa.expires = expires
                    else:
                        # pa.expires is None, no need to refill it
                        pass

                else:
                    pa = ProfileArg(profile=profile, name=ga.name, value=ga.value, expires=expires)
                pa.save()

    def __str__(self):
        return self.name


class Membership(models.Model):
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE)
    # group = models.ForeignKey(Group, on_delete=models.CASCADE)
    groupname = models.CharField(max_length=200)

    granted = models.DateTimeField(default=timezone.now)  # when user got this userlevel first
    expires = models.DateTimeField(null=True, blank=True)
    # refilled = models.DateTimeField(default=timezone.now)  # when last time refilled (e.g. always not more then 30d old)

    lastcron = 0
    crontime = 3600

    rid = models.CharField(max_length=100, default='', db_index=True)

    def __str__(self):
        username = safe_getattr(self, 'profile.user.username')

        return "Membership {u} in {g} exp {exp}".format(u=username, g=self.groupname,
                                                        exp=self.expires if self.expires else "NEVER")

    def getdec(profile, name):
        print("getdec {}".format(name))
        pass

    # membership.get_static_arg
    def get_static_arg(self, name, default=None):
        plan = settings.PLANS[self.groupname]
        value = plan.get(name, default)
        return value

    # membership.get_static_arg_prefix
    def get_static_arg_prefix(self, argprefix, default=None):
        gconf = settings.PLANS[self.groupname]
        for argname in gconf:
            if argname.startswith(argprefix):
                return argname, gconf[argname]
        return None

    def get_weight(self):
        w = self.get_static_arg('_weight')
        if w:
            return w

        w = self.get_static_arg('_price')
        if w:
            return w

        w = self.get_static_arg('maxindicators')
        if w:
            return w

        return 1
        # return settings.PLANS[self.groupname].get('_weight', 0)


    # membership.cron
    @classmethod
    def cron(cls):

        if time.time() - cls.lastcron < cls.crontime:
            return

        WarnExpName = 'WarnExpiration'

        fixexpire = timezone.now() + datetime.timedelta(days=30)
        newexpire = timezone.now() + datetime.timedelta(days=60)

        # renew _autorenew groups

        #for group in Group.objects.all():
        #    if group.get_static_arg('_autorenew'):
        #        r = group.membership_set.filter(expires__lt=fixexpire).update(expires=newexpire)
        #        log.info("_autorenew updated: {}".format(r))

        # renew variables in group
        #for m in Membership.objects.all():
        #    renewtime = m.refilled + datetime.timedelta(seconds=m.group.refillperiod)
        #    if timezone.now() > renewtime:
        #        log.info("renew membership {} in group {}".format(
        #            m.profile.user.username, m.group.name))
        #        m.group.refill(m.profile, m.expires)
        #        m.refilled = timezone.now()
        #        m.save()

        # expire expired arguments and groups
        ProfileArg.expire()

        for m in Membership.objects.filter(expires__lt=timezone.now()):
            log.info("delete expired membership {} in group {}".format(
                m.profile.user.username, m.groupname))
            m.delete()

        # warn N days before expiration
        for warntimestr in ['7d', '1d']:
            dt = str2dt(warntimestr)
            expmoment = timezone.now() + dt
            for m in Membership.objects.filter(expires__lt=expmoment, profile__ci=myci()):
                expstr = m.expires.strftime('%Y%m%d')
                timeleft = chopms(m.expires - timezone.now())
                thname = 'WarnMembershipExpires:' + m.profile.user.username + ':' + m.groupname + ':' + expstr + ':' \
                         + warntimestr

                try:
                    Throttle.get(thname)
                    # found, no need to warn
                    continue
                except Throttle.DoesNotExist:
                    # not found, good
                    pass

                log.info("warn user {} about expirations of group {} at {} in {}".format(
                    m.profile.user.username, m.groupname, expstr, warntimestr))

                # send email

                subj = 'okerr IMPORTANT warning (expiration)'

                tpl_plain = get_template('warnexpire-email.txt')
                tpl_html = get_template('warnexpire-email.html')

                ctx = {'user': m.profile.user, 'profile': m.profile,
                       'membership': m, 'timeleft': timeleft,
                       'hostname': settings.HOSTNAME}

                # ctx = Context({'user': m.profile.user, 'profile': m.profile,
                #    'membership': m, 'timeleft': timeleft,
                #    'hostname': settings.HOSTNAME})

                content_plain = tpl_plain.render(ctx)
                content_html = tpl_html.render(ctx)

                msg = EmailMultiAlternatives(subj, content_plain,
                                             settings.FROM, [m.profile.user.username])
                msg.attach_alternative(content_html, "text/html")
                msg.send()

                # save that we notified this user about this N days
                Throttle.add(thname, expires=datetime.timedelta(days=30))

        cls.lastcron = time.time()

    # membership.touch
    def touch(self, touchall=False):
        # no mtime here
        # te = TransactionEngine()
        # te.update_instance(self)
        pass

    # membership.tsave
    def tsave(self):
        uni_tsave(self)


class GroupArg(models.Model):
    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    name = models.CharField(max_length=200)
    value = models.IntegerField()

    def __str__(self):
        return "{} = {}".format(self.name, self.value)


class SystemVariable(models.Model):
    name = models.CharField(max_length=200)
    value = models.TextField(default='')

    def __str__(self):
        return "{}: {}".format(self.name, self.value)

    @staticmethod
    def get(name, default=None):
        try:
            sv = SystemVariable.objects.get(name=name)
            return sv.value
        except ObjectDoesNotExist:
            return default

    @staticmethod
    # systemvariable.assign
    def assign(name, value):
        try:
            sv = SystemVariable.objects.get(name=name)
            sv.value = value
        except ObjectDoesNotExist:
            sv = SystemVariable.objects.create(name=name, value=value)
        sv.save()

    @staticmethod
    def reinit():
        SystemVariable.assign('lastloopunixtime', '0')
        SystemVariable.assign('process-backlog', '999999')
        SystemVariable.assign('install-time', time.strftime('%Y%m%d%H%M'))

    #        SystemVariable.assign('maintenance','1')
    #        SystemVariable.assign('maintenance_msg','Maintenance. Please retry in 10-15 minutes...')

    # systemvariable.fix_static
    @staticmethod
    def fix_static(verbose, save):
        defvars = {
            'lastloopunixtime': '0',
            'process-backlog': '999999',
            'install-time': time.strftime('%Y%m%d%H%M'),
            #            'maintenance': '0',
            #            'maintenance_msg': 'Maintenance. Please retry in 10-15 minutes...'
        }

        for vname, vval in defvars.items():
            if SystemVariable.get(vname, None):
                if verbose:
                    print("{} exists".format(vname))
            else:
                if save:
                    print("fix sysvar {}".format(vname))
                    SystemVariable.assign(vname, vval)
                else:
                    print("missing sysvar {}. use --save to fix to {}".format(vname, vval))


class ProfileArg(models.Model):
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE)
    # group = models.ForeignKey(Group, on_delete=models.CASCADE, null=True)
    name = models.CharField(max_length=200)
    value = models.IntegerField()
    expires = models.DateTimeField(null=True)  # if not set - never expires
    visible = models.BooleanField(default=True)
    rid = models.CharField(max_length=100, default='', db_index=True)

    def __str__(self):
        return "{user}.{gname}.{name} = {value} ({exp})".format(
            user=safe_getattr(self, 'profile.user.username'),
            gname=safe_getattr(self, 'groupname'),
            name=self.name, value=self.value,
            exp=self.expires if self.expires else "never")

    @staticmethod
    def expire():
        ProfileArg.objects.filter(expires__lt=timezone.now()).delete()

class ProjectMember(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    # unused_user = models.ForeignKey(settings.AUTH_USER_MODEL)
    # user email
    email = models.CharField(max_length=200, default='')
    iadmin = models.BooleanField(default=False)  # manage indicators
    tadmin = models.BooleanField(default=False)  # manage project, 'admin'. TeamAdmin.
    mtime = models.DateTimeField(auto_now=True)
    rid = models.CharField(max_length=100, default='', db_index=True)

    # projectmember.fix
    def fix(self, verbose=False):
        fixed = False

        if self.email == self.project.owner.email:

            if not self.iadmin:
                if verbose:
                    print("{} iadmin must be true".format(self))
                self.iadmin = True
                fixed = True

            if not self.tadmin:
                if verbose:
                    print("{} tadmin must be true".format(self))
                self.tadmin = True
                fixed = True
        return fixed

    # projectmember.touch
    def touch(self, touchall=False):
        set_rid(self)
        self.mtime = timezone.now()

        # te = TransactionEngine()
        # te.update_instance(self)

        if touchall:
            self.save()
            self.project.touch(touchall)

    # projectmember.tsave
    def tsave(self):
        uni_tsave(self)

    def __str__(self):
        return "user: {} project: {} {}{}".format(
            safe_getattr(self, 'email'),
            safe_getattr(self, 'project.name'),
            "[iadmin]" if self.iadmin else "",
            "[tadmin]" if self.tadmin else "")


"""
class IndicatorTag(models.Model):
    name = models.CharField(max_length=200)
    indicator = models.ForeignKey(Indicator) # was null=True, dont know why
    project = models.ForeignKey(Project)

    def __str__(self):
        return self.name
"""


# ProjectMember - Indicator arguments
class IArg(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    indicator = models.ForeignKey(Indicator, on_delete=models.CASCADE, null=True)
    name = models.CharField(max_length=200)
    value = models.CharField(max_length=200)
    valtype = models.CharField(max_length=1)  # 'S'tring, 'I'nteger or 'B'oolean

    def __str__(self):
        return "{} ({}) {}".format(self.name, self.valtype, self.value)


class IChange(models.Model):
    indicator = models.ForeignKey(Indicator, on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True)
    oldstate = models.CharField(max_length=200, null=True)
    newstate = models.CharField(max_length=200)

    def __str__(self):
        return "{} {} -> {}".format(shortdate(self.created), self.oldstate, self.newstate)

    # ichange.cron
    @staticmethod
    def cron():
        # delete old records
        now = timezone.now()
        old = now - settings.ICHANGE_AGE
        IChange.objects.filter(created__lt=old).delete()


class IndicatorTree():
    # indicatortree.init

    tree = None
    prefix = None

    branches = None
    indicators = None
    sumstatus = None

    ni = None  # number indicators in this subtree
    nitotal = None  # ni + deeper
    tags = None

    def __init__(self, prefix=None):
        # print "indicatortree init, prefix={}".format(prefix)
        self.tree = dict()
        self.prefix = prefix
        self.branches = dict()
        self.indicators = list()
        self.sumstatus = dict(OK=0, ERR=0, MAINTENANCE=0, SILENT=0, PENDING=0)
        self.ni = 0
        self.nitotal = 0
        self.tags = dict()

    # indicatortree.add
    # only root node can use it
    def add(self, i):
        # only if matches tags filter
        if self.tags:
            itags = i.tags()
            for tag in self.tags:
                if self.tags[tag] == '+':
                    if not tag in itags:
                        # no required tag
                        return
                if self.tags[tag] == '-':
                    if tag in itags:
                        # has forbidden tag
                        return

        ip = i.name.split(':')[:-1]
        if ip:
            self.add2path(ip, i)
        else:
            self.add2path(None, i)

    # indicatortree.addpath
    def add2path(self, path, indicator):
        # print "add2path {} {}".format(path,indicator)

        self.sumstatus[indicator.okerrm()] += 1
        if indicator.pending():
            self.sumstatus['PENDING'] += 1

        # if indicator.silent:
        #    self.sumstatus['SILENT']+=1

        self.nitotal += 1

        if not path:
            # add locally
            self.indicators.append(indicator)
            self.ni += 1
        else:
            bname = path[0]
            # print "{}: add to path {} branch {}".format(self.prefix,path,bname)
            if path[0] in self.branches:
                b = self.branches[bname]
            else:
                # new prefix
                if self.prefix is None:
                    bprefix = bname
                else:
                    bprefix = ':'.join([self.prefix, bname])
                b = IndicatorTree(bprefix)
                self.branches[bname] = b
            b.add2path(path[1:], indicator)

    # indicatortree.dump
    def dump(self, spaces=0):
        s = ' ' * spaces

        if self.prefix:
            myname = self.prefix
        else:
            myname = 'root'

        print("{}{} ({}/{}: {}):".format(s, myname, self.ni, self.nitotal, str(self.sumstatus)))

        if self.indicators:
            # print "{}indicators:".format(s)
            for i in self.indicators:
                print("{}{}".format(s + '  ', i))

        # print "{}branches:".format(s)
        for b in self.branches:
            # print "{}branch: {}".format(s,b)
            self.branches[b].dump(spaces + 2)

    def __str__(self):
        return "IndicatorTree, nitotal: {} sum: {}".format(self.nitotal, self.sumstatus)

    def uid(self):
        if self.prefix:
            return hashlib.sha1(self.prefix).hexdigest()
        else:
            return "root-itree"

    #
    # return True if all [sub]indicators 'isok'
    # isok is if okerrm is not ERR
    #
    def isok(self):
        for i in self.indicators:
            # print "check indicator {} {}".format(i.name, i.okerrm())
            if i.okerrm() == 'ERR':
                # print "error"
                return False

        for bname, b in self.branches.items():
            if not b.isok():
                return False

        return True

    def hasflag(self, fname):
        for i in self.indicators:
            print("check indicator {} {}".format(i.name, i.okerrm()))
            if fname in i.flags():
                return True

        for bname, b in self.branches.items():
            if not b.hasflag(fname):
                return True
        return False

    # if non-zero counters

    def sumok(self):
        if self.sumstatus['OK']:
            return True
        else:
            return False

    def simulate(self):
        print("prefix: {}".format(self.prefix))
        for b in self.branches:
            print("branch {}".format(b))
            br = self.branches[b].simulate()
        for i in self.indicators:
            print(i.name)

    def settags(self, tags):
        self.tags = tags


class StatusPage(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    addr = models.CharField(max_length=200)  # e.g. servers
    title = models.CharField(max_length=200)  # e.g. Status of servers
    public = models.BooleanField(default=False)
    can_subscribe = models.BooleanField(default=False)
    desc = models.TextField(default='')

    def __str__(self):
        return '{}/{} pub: {} title: {} ({} indicators)'.format(self.project.get_textid(), self.addr, self.public,
                                                                 self.title, self.statusindicator_set.count())

    # statuspage.export
    def export(self):
        d = dict()
        d['addr'] = self.addr
        d['textid'] = self.project.get_textid()
        d['name'] = self.project.name
        d['title'] = self.title
        d['desc'] = self.desc
        d['chapters'] = dict()

        for si in self.statusindicator_set.all():
            if si.chapter not in d['chapters']:
                d['chapters'][si.chapter] = list()
            d['chapters'][si.chapter].append(si.export())

        d['blog'] = list()
        for blog_record in self.blogrecords():
            d['blog'].append(blog_record.export())

        return d

    def all_si(self):
        return self.statusindicator_set.order_by('weight')

    def get_code(self, email, purpose):
        vc = VerificationCode()
        return vc.get_code(email, purpose)

    def verify_code(self, datecode, email, purpose, usercode):
        vc = VerificationCode()
        return vc.verify_code(datecode, email, purpose, usercode)

    def is_subscribed(self, email):
        return self.statussubscription_set.filter(email=email).count() > 0

    def get_chapters(self):
        ch = dict()
        weights = dict()
        out = collections.OrderedDict()

        for si in self.statusindicator_set.all():
            if not si.chapter in ch:
                ch[si.chapter] = list()
                weights[si.chapter] = si.weight

            ch[si.chapter].append(si)

            if si.weight < weights[si.chapter]:
                weights[si.chapter] = si.weight

        chw = sorted(weights.keys(), key=lambda x: weights[x])
        for chapter in chw:
            out[chapter] = list()
            for si in sorted(ch[chapter], key=lambda x: x.weight):
                out[chapter].append(si)

        return out

    def blogrecords(self):
        return self.statusblog_set.order_by('-created')[:5]


class StatusIndicator(models.Model):
    status_page = models.ForeignKey(StatusPage, on_delete=models.CASCADE)
    indicator = models.ForeignKey(Indicator, on_delete=models.CASCADE)
    details = models.BooleanField(default=False)
    weight = models.IntegerField(default=1000)
    title = models.CharField(max_length=200)  # e.g. servers
    chapter = models.CharField(max_length=200, default='')  # e.g. servers
    desc = models.TextField(default='')  # e.g. servers

    def __str__(self):
        return '{}: {}'.format(self.status_page.addr, self.indicator.name)

    # statusindicator.export
    def export(self):
        d = dict()
        d['title'] = self.title
        d['desc'] = self.desc
        d['chapter'] = self.chapter
        d['weight'] = self.weight
        d['status'] = self.indicator.status
        if self.details:
            d['details'] = self.indicator.details
        else:
            d['details'] = None
        d['updated'] = self.indicator.updated.strftime("%d/%m/%Y %H:%M:%S")
        d['changed'] = self.indicator.changed.strftime("%d/%m/%Y %H:%M:%S")

        d['updated_age'] = str(chopms(timezone.now() - self.indicator.updated))
        d['changed_age'] = str(chopms(timezone.now() - self.indicator.changed))


        return d

class StatusSubscription(models.Model):
    status_page = models.ForeignKey(StatusPage, on_delete=models.CASCADE)
    email = models.CharField(max_length=200)  # e.g. servers
    ip = models.CharField(max_length=200)  # e.g. servers
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return '{}: {}'.format(self.status_page.addr, self.email)


class StatusBlog(models.Model):
    status_page = models.ForeignKey(StatusPage, on_delete=models.CASCADE)
    created = models.DateTimeField(default=timezone.now)
    text = models.TextField(default='')  # e.g. servers

    def __str__(self):
        return "StatusBlog ({})".format(shortdate(self.created))

    # statusblog.export
    def export(self):
        return {'created': self.created.strftime("%d/%m/%Y %H:%M:%S"), 'text': self.text}

    def send_updates(self, base_url):
        for ss in self.status_page.statussubscription_set.all():
            email = ss.email

            # plaintext = get_template('statuspage-subscribe.txt')
            htmly = get_template('statuspage-update.html')

            d = dict()
            d['sp'] = self.status_page
            d['project'] = self.status_page.project
            d['datecode'], d['code'] = self.status_page.get_code(email, 'unsubscribe')
            d['email'] = email
            d['hostname'] = settings.HOSTNAME
            d['prefix'] = 'https://cp.okerr.com'
            d['base_url'] = base_url
            d['text'] = self.text

            d['hostname'] = settings.HOSTNAME,
            d['MYMAIL_FOOTER'] = settings.MYMAIL_FOOTER

            # text_content = plaintext.render(d)
            html_content = htmly.render(d)
            subject = '{}'.format(self.status_page.title)

            send_email(email, subject=subject, html=html_content, what="status blog update")

            log.info('sent blog update for {}/{} to {}'.format(
                self.status_page.project.get_textid(),
                self.status_page.addr,
                ss.email))


class Throttle(models.Model):
    key = models.CharField(max_length=200)
    priv = models.CharField(max_length=200)
    created = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField()

    @staticmethod
    def add(key, priv=None, expires=None):
        th = Throttle()
        th.key = key

        if expires is None:
            th.expires = timezone.now() + datetime.timedelta(hours=1)
        else:
            th.expires = timezone.now() + expires

        th.priv = priv if priv is not None else ''
        th.save()

    @staticmethod
    def get(key):
        return Throttle.objects.get(key=key, expires__gt=timezone.now())

    # throttle.cron
    @classmethod
    def cron(cls):
        now = timezone.now()
        cls.objects.filter(expires__lt=now).delete()

    def __str__(self):
        return '{} ({}) {}'.format(self.key, self.priv, chopms(self.expires - timezone.now()))


class DynDNSRecord(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    method = models.CharField(max_length=200, default=None)  # dyndns method

    name = models.CharField(max_length=200, default='www', null=False, blank=False)

    hostname = models.CharField(max_length=200, default='www', null=False, blank=False)
    domain = models.CharField(max_length=200, default=None, null=True)

    login = models.CharField(max_length=200, default=None, null=True)
    secret = models.CharField(max_length=200, default=None, null=True)
    curvalue = models.CharField(max_length=200, default=None, null=True)
    curpriority = models.IntegerField(default=100)

    push = models.BooleanField(default=False, db_index=True)  # if retry needed
    scheduled = models.DateTimeField(default=timezone.now, blank=True, db_index=True)
    nfails = models.IntegerField(default=0)

    last_try = models.DateTimeField(default=timezone.now)
    changed = models.DateTimeField(default=timezone.now)
    status = models.TextField(default=None, null=True)
    cache = models.TextField(default='')

    class Meta:
        unique_together = ('hostname', 'domain')

    # def_method = 'okerr/yapdd'
    def_method = 'okerr/cloudflare'

    @classmethod
    # dyndnsrecord.cron
    def cron(cls):
        for ddr in cls.objects.filter(push=True, scheduled__lte=timezone.now(), project__ci=myci()).all():
            ddr.push_value()
            ddr.save()

    def methods(self, enabled=True):
        m = {
            'yapdd': {
                'name': 'pdd.yandex.ru (OBSOLETE)',
                'fields': ['secret', 'hostname', 'domain'],
                'disabled': True
            },
            'okerr/yapdd': {
                'name': 'pdd.yandex.ru (okerr account for testing. OBSOLETE)',
                'fields': ['hostname'],
                'override': {
                    'domain': 'dyn1.okerr.com',
                    'hostname': '{hostname}.{textid}'
                },
                'disabled': True
            },
            'okerr/cloudflare': {
                'name': 'CloudFlare (okerr account for testing)',
                'fields': ['hostname'],
                'override': {
                    'domain': 'okerr.com',
                    'hostname': '{hostname}.{textid}.dyn'
                }
            },
            'cloudflare': {
                'name': 'cloudflare.com',
                'fields': ['login', 'secret', 'domain', 'hostname'],
                'help': {
                    'login': 'your username (email) on cloudfire',
                    'secret': 'API key. Get it at cloudfire.com, My Profile, Global API Key'
                }
            },
            'he.net': {
                'name': 'dns.he.net dynamic dns',
                'fields': ['secret', 'hostname', 'domain']
            }
        }

        if enabled:
            # return ALL items
            mfiltered = {k: v for (k, v) in m.items() if not 'disabled' in v or not v['disabled'] or k == self.method}
            return mfiltered
        else:
            return m

    #
    # get ddr fields as dict (only needed fields)
    #
    def get_fields(self):
        fields = list()
        try:
            m = self.methods()[self.method]
            for fname in m['fields']:
                name = fname
                value = getattr(self, fname)
                try:
                    help = m['help'][name]
                except KeyError:
                    help = None

                fields.append((name, value, help))

            return fields
        except KeyError:
            return fields

    # return default priority for new indicator
    def getdefpriority(self):
        default = 1000

        minprio = self.dyndnsrecordvalue_set.aggregate(Min('priority'))['priority__min']

        if minprio is None:
            return default

        return minprio - 10

    #
    # set fields from POST/dict
    #
    def set_fields(self, d):
        try:
            for fname in self.methods()[self.method]['fields']:
                if fname in d:
                    setattr(self, fname, d[fname])
        except KeyError:
            pass

    def __str__(self):

        pushline = "local" if self.push else "synced"

        return "{}@{} {} {} = {} {}".format(
            self.hostname, self.project.get_textid(), self.method,
            self.fqdn(), self.curvalue, pushline)

    def fqdn(self):

        domain = self.get_domain()
        hostname = self.get_hostname()

        if hostname:
            if domain:
                return hostname + '.' + domain
            else:
                return hostname
        else:
            return domain

    def left(self):
        return "{}.{}".format(self.hostname, self.project.get_textid())

    def set_value(self, force=False):
        defvalue = None
        value = None
        defpriority = None
        priority = None

        for ddrv in self.values():
            if not defvalue:
                defvalue = ddrv.value
                defpriority = ddrv.priority
            if ddrv.indicator.status == 'OK' and not ddrv.indicator.maintenance:
                value = ddrv.value
                priority = ddrv.priority
                break

        value = value or defvalue
        priority = priority or defpriority

        if force or value != self.curvalue:
            # new value
            self.curvalue = value
            self.curpriority = priority
            self.push = True
            self.nfails = 0
            self.scheduled = timezone.now()
            self.changed = timezone.now()
            self.log("New failover value {} (pri: {})".format(self.curvalue, self.curpriority))

    def status_age(self):
        if self.curvalue is None:
            return ('not configured', 0)

        if self.push:
            # how long not synced
            if self.last_try > self.changed:
                return ('retry', dhms(timezone.now() - self.last_try))
            else:
                return ('wait', dhms(timezone.now() - self.changed))
        else:
            return ('synced', dhms(timezone.now() - self.last_try))

    def get_domain(self):
        try:
            m = self.methods()[self.method]
        except KeyError:
            m = dict()

        domain = self.domain

        if 'override' in m:
            d = {
                'textid': self.project.get_textid(),
                'hostname': self.hostname
            }

            if 'domain' in m['override']:
                domain = m['override']['domain'].format(**d)

        return domain

    def get_hostname(self):
        try:
            m = self.methods()[self.method]
        except KeyError:
            m = dict()

        hostname = self.hostname

        if 'override' in m:
            d = {
                'textid': self.project.get_textid(),
                'hostname': self.hostname
            }

            if 'hostname' in m['override']:
                hostname = m['override']['hostname'].format(**d)

        return hostname

    # dyndnsrecord.title
    def title(self):
        # return ':'.join([self.hostname or '', self.domain or ''])
        return self.fqdn()

    # dyndnsrecord.log
    def log(self, message):
        self.project.log(self.title() + ' ' + message, typecode='dyndns')

    def logrecords(self):
        return self.project.logrecord_set.filter(typecode=LogRecord.get_typecode('dyndns'),
                                                 message__startswith=self.title())

    # called from cron. no need to call directly
    def push_value(self):
        m = self.methods()[self.method]

        delay_sch = [0, 30, 60, 300, 3600, 7200]
        max_delay = delay_sch[-1]

        domain = self.get_domain()
        hostname = self.get_hostname()

        record = DynDNS(
            method=self.method,
            hostname=hostname,
            domain=domain,
            login=self.login,
            secret=self.secret,
            cache=self.cache)

        try:
            msg = record.set_record(self.curvalue)
        except (requests.exceptions.RequestException, DDNSExc) as e:
            self.last_try = timezone.now()
            self.status = str(e)
            log.info("Failed to set {} = {}: {}".format(self.fqdn(), self.curvalue, str(e)))
            self.log("Failed to set {} = {}: {}".format(self.fqdn(), self.curvalue, str(e)))

            try:
                delay_sec = delay_sch[self.nfails]
            except IndexError:
                delay_sec = max_delay

            delay = datetime.timedelta(seconds=delay_sec)

            self.nfails += 1
            self.scheduled = timezone.now() + delay
            self.log("Next retry scheduled at: {0:%Y-%m-%d %H:%M:%S}".format(self.scheduled))

        else:
            self.last_try = timezone.now()
            self.status = msg
            self.push = False
            self.log("successfully set {} = {} in {} DNS".format(self.fqdn(), self.curvalue, self.method))

    def get_real_value(self):
        fqdn = self.fqdn()

        if not fqdn:
            return None
        try:
            return socket.gethostbyname(self.fqdn())
        except socket.gaierror:
            return None

    def values(self):
        return self.dyndnsrecordvalue_set.order_by('-priority')

    def indicators(self):
        return Indicator.objects.filter(dyndnsrecordvalue__ddr=self)


class DynDNSRecordValue(models.Model):
    ddr = models.ForeignKey(DynDNSRecord, on_delete=models.CASCADE, default=None)
    indicator = models.ForeignKey(Indicator, on_delete=models.CASCADE)
    priority = models.IntegerField(default=100)
    value = models.CharField(max_length=200)  # e.g. 1.2.3.4

    def __str__(self):
        return "{}({}) = {} ({})".format(self.indicator.name, self.indicator.status, self.value, self.priority)

class Oauth2Binding(models.Model):
    profile = models.ForeignKey(Profile, on_delete=models.CASCADE, db_index=True)
    provider = models.CharField(max_length=200)  # e.g. gmail
    uid = models.CharField(max_length=200, db_index=True)  # e.g. unique id of this user on provider

    class Meta:
        unique_together = ('profile', 'provider')

    def __str__(self):
        return 'Oauth2Binding:{}:{}'.format(self.provider, self.profile.user.email)

    @classmethod
    def bind(cls, profile, provider, uid):
        b = Oauth2Binding(profile=profile, provider=provider, uid=uid)
        b.save()

    @classmethod
    def rmprofile(cls, profile):
        return cls.objects.filter(profile=profile).delete()

    @classmethod
    def bound(cls, profile, provider):
        try:
            bind = Oauth2Binding.objects.get(profile=profile, provider=provider)
            return True
        except cls.DoesNotExist:
            return False

    @classmethod
    def get_profiles(cls, provider, uid):
        return cls.objects.filter(provider=provider, uid=uid)



#
# reqs:
# - secret generate/verify
# - verify by secret
# - verify by URL
# - reactivation
#

class BonusException(Exception):
    pass

class BonusNotFound(BonusException):
    pass

class BonusVerificationFailed(BonusException):
    pass

class Bonus:
    def __init__(self, name, prefix, group, days, expires=None, repeat=None, verify_url=None, secret=None,
                 reactivation=None, verification=None, discard_if_failed=None):
        self.name = name
        self.prefix = prefix
        self.group = group
        # self.expires = expires
        self.repeat = repeat
        self.verify_url = verify_url
        self.secret = secret
        self.verification = verification

        if isinstance(expires, str):
            self.expires = timezone.make_aware(datetime.datetime.strptime(expires, "%Y-%m-%d"))
        else:
            # here expires is datetime or None, but not str
            self.expires = expires

        if isinstance(days, int):
            self.days = datetime.timedelta(days=days)
        else:
            self.days = days

        if isinstance(discard_if_failed, int):
            self.discard_if_failed = datetime.timedelta(days=discard_if_failed)
        else:
            self.discard_if_failed = discard_if_failed

        if isinstance(repeat, int):
            self.repeat = datetime.timedelta(days=repeat)
        else:
            self.repeat = repeat

        if isinstance(reactivation, int):
            self.reactivation = datetime.timedelta(days=reactivation)
        else:
            self.reactivation = reactivation


    @classmethod
    def get_by_name(cls, name):
        for b in settings.BONUS_CODES:
            if b['name'] == name:
                return cls.from_dict(b)
        raise BonusNotFound

    @classmethod
    def get_by_code(cls, code, internal=False):
        for b in settings.BONUS_CODES:
            if code.startswith('_') and not internal:
                continue

            prefix = b.get('prefix') or b['name']

            if prefix.endswith(':') and code.startswith(prefix) or code == prefix:
                bonus = cls.from_dict(b)
                if bonus.expired():
                    continue

                return bonus
        raise BonusNotFound

    @classmethod
    def names(cls):
        for b in settings.BONUS_CODES:
            yield b['name']

    @classmethod
    def from_dict(cls, d):

        bonus = cls(
            name=d['name'],
            prefix=d.get('prefix') or d['name'],
            group=d.get('group'),
            days=d.get('days'),
            expires=d.get('expires'),
            repeat=d.get('repeat'),
            verify_url=d.get('verify_url'),
            verification=d.get('verification'),
            secret=d.get('secret'),
            reactivation=d.get('reactivation'),
            discard_if_failed=d.get('discard_if_failed')
        )
        return bonus

    def __str__(self):
        return "{}: {}* {} ({})".format(self.name, self.prefix, self.group, self.days)

    def expired(self):
        return self.expires is not None and timezone.now() > self.expires

    def apply(self, profile, code):

        print("Apply.. ..")
        if self.group:
            group = self.group
        else:
            m = profile.get_best_membership()
            group = m.groupname

        print("Group:", group)

        # check if blocked?
        if profile.bonusactivation_set.filter(profile=profile, name=self.name).count() > 0:
            raise BonusVerificationFailed('Already applied bonuscode {} to profile {}'.format(self.name, profile))

        self.verify(code)

        profile.assign(group=group, time=self.days, add=True)

        if self.reactivation:
            reactivation = timezone.now() + self.reactivation
        else:
            reactivation = None

        if self.repeat is None:
            expiration = None
        else:
            expiration = timezone.now() + self.repeat

        ba = BonusActivation(
            profile=profile,
            name=self.name,
            code=code,
            activated=timezone.now(),
            reactivation=reactivation,
            expiration=expiration
        )

        ba.save()

    def reapply(self, profile, code):
        self.verify(code)
        if self.group:
            group = self.group
        else:
            m = profile.get_best_membership()
            group = m.groupname
        log.info("Reapply group {} to {} for {}".format(group, profile.user.email, self.days))
        profile.assign(group=group, time=self.days, add=False)

    def generate(self, value=None):
        if self.verification == 'hmac:sha256':
            value = value or ''.join(random.choice(string.ascii_lowercase+string.digits) for i in range(20))
            mac = hmac.new(self.secret.encode(), msg=self.name.encode() + value.encode()).hexdigest()
            return '{}{}:{}'.format(self.prefix, value, mac)
        else:
            return None

    def verify(self, code):
        if self.expired():
            raise BonusVerificationFailed('BonusCode expired')

        if self.verification == 'hmac:sha256':
            name, value, mac = code.split(':')
            mac2 = hmac.new(self.secret.encode(), msg=self.name.encode() + value.encode()).hexdigest()
            if mac != mac2:
                raise BonusVerificationFailed('Failed MAC verification')

        elif self.verification == 'url:200':
            if '.' in code:
                raise BonusVerificationFailed('Incorrect code')

            url = self.verify_url.format(CODE=code)
            # print(url)
            r = requests.get(url, allow_redirects=True)
            if r.status_code != 200:
                raise BonusVerificationFailed('Failed network verification')

    def dump(self):
        print("DUMP", self)
        for ba in BonusActivation.objects.filter(name=self.name):
            print(ba)


class BonusActivation(models.Model):
    class Meta:
        app_label = 'okerrui'

    profile = models.ForeignKey(Profile, on_delete=models.CASCADE)
    # BonusCode = models.ForeignKey(BonusCode, on_delete=models.CASCADE, null=True)
    name = models.CharField(max_length=200, null=True, default=None)  # bonus code name
    code = models.CharField(max_length=200, null=True, default=None)  # bonus code itself
    activated = models.DateTimeField(default=timezone.now, blank=True)
    reactivation = models.DateTimeField(null=True, default=None)  # check and apply at that time
    expiration = models.DateTimeField(null=True, default=None)  # delete at that time. (none: keep forever)
    verification_failed_since = models.DateTimeField(null=True, default=None)

    @staticmethod
    # bonusactivation.cron
    def cron(all_records=False):

        #
        # extend (reapply)
        #
        # delete old
        #
        now = timezone.now()

        if all_records:
            qs = BonusActivation.objects.filter(reactivation__isnull=False)
        else:
            qs = BonusActivation.objects.filter(reactivation__isnull=False, reactivation__lt=now)

        for ba in qs:
            try:
                code = Bonus.get_by_name(ba.name)
                code.reapply(profile=ba.profile, code=ba.code)
                ba.reactivation = now + code.reactivation
                ba.verification_failed_since = None
                ba.save()
            except BonusNotFound as e:
                log.info("ZZZZ not bonus for BA {}".format(ba))
                ba.delete()
            except BonusVerificationFailed as e:
                log.info("ZZZ exception: {}".format(e))
                if ba.verification_failed_since is None:
                    ba.verification_failed_since = timezone.now()

                if code.discard_if_failed and (timezone.now() - ba.verification_failed_since) > code.discard_if_failed:
                    # discard this BA
                    log.info("Delete BA: {} (failed since: {})".format(ba, ba.verification_failed_since))
                    ba.delete()
                else:
                    ba.reactivation = now + code.reactivation
                    ba.save()


        #
        # delete expired
        #
        for ba in BonusActivation.objects.filter(expiration__isnull=False, expiration__lt=now):
            log.info("{} expire".format(ba))
            ba.delete()

    def __str__(self):
        return "#{} {} {} {} ({}) reactivation: {} expiration: {}".format(
            self.id,
            shortdate(self.activated),
            self.profile.user.email,
            self.name,
            self.code,
            self.reactivation,
            self.expiration)

