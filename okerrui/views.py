from django.shortcuts import get_object_or_404, render, redirect
from django.http import HttpResponseRedirect, HttpResponseBadRequest, HttpResponseForbidden, HttpResponse, HttpResponseNotFound
# from django.core.urlresolvers import reverse
from django.urls import reverse
from django.views import generic
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login as django_login
from django import forms
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied
from django.forms.models import modelformset_factory
from django.forms.formsets import formset_factory
from django.forms import ModelForm
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.db import connection, transaction
from django.db.models import Count, Q, ProtectedError
from django.conf import settings
from django.template.loader import get_template
from django.template import Context
from django.core.mail import EmailMultiAlternatives, mail_admins
from django.utils.translation import ugettext_lazy as _, pgettext
from django.contrib.auth import get_user_model
from oauth2_provider.views.generic import ProtectedResourceView
from django.http import Http404
from django.utils.translation import to_locale, get_language

import requests_oauthlib
import oauthlib

import requests

from operator import itemgetter
import operator
import datetime
import string
import time
import json
from myutils import shortstr, unixtime2dt, dt2unixtime, \
    get_remoteip, send_email, timesuffix2sec, dhms, strcharset, \
    nsresolve, get_redis, get_verified_reverse
from tree import Tree
import myutils
import re
import logging
import base64
import hmac
import hashlib
import shlex
import socket
import os
import sys
import random
from urllib.parse import urljoin
#import urllib.parse
from pprint import pprint

from validate_email import validate_email
from netaddr import IPNetwork, IPAddress, AddrFormatError

from okerrui.models import (
    
    Indicator,
    LogRecord,
    CheckMethod,
    Profile,
    CheckArg,
    # CheckArgVal,
    Policy,
    PolicySubnet,
    ProfileArg,
    Project,
    ProjectMember,
    ProjectAccessKey,
    ProjectTextID,
    ProjectInvite,
    StatusPage,
    StatusIndicator,
    StatusBlog,
    StatusSubscription,
    SystemVariable,
    Throttle,
    IChange,
    Group,
    DynDNSRecord,
    DynDNSRecordValue,
    Oauth2Binding
    )

from okerrui.exceptions import OkerrError

# import okerr.settings_oauth
from okerrui.cluster import RemoteServer, myci

# from transaction.models import TransactionEngine, Transaction, TransactionError, TransactionServer
# from transaction.models import TransactionServer


# from moveauth.models import MoveAuthTicket

import okerrui.datasync
from okerrui.impex import Impex

from logmessage.models import LogMessage, Logger

#log=myutils.openlog()
#log.info('{} opened log'.format(time.time()))
#log.info('handlers: {}'.format(log.handlers))


REMOTE_NETPROCESS_EXPIRATION = 300


log = logging.getLogger('okerr')
logger = Logger()

"""

    when change CM, make sure all args are exists (or create it if needed).
    then simple use formset and disable adding

"""


# utility subroutines

#
# textable:
# return True if keylist is 'textable' (sequence-code)
#
def textable(keylist):
    for k in keylist:
        if k.isdir():
            return False
        try:
            int(k.name)
        except ValueError:
            return False
    return True


# get Project by project, username and password

#
# returns:
# project if good auth and user is member of project
#
# otherwise, exception
#

def getProjectHTTPAuth(request, textid, level='member'):
#    noauth = HttpResponse("Auth Required", status = 401)
#    noauth['WWW-Authenticate'] = 'Basic realm="okerr"'

    api_key = request.headers.get('X-API-KEY', None)
    project = Project.get_by_textid(textid)

    if project is None:
        raise Http404('No such project with textid {}'.format(textid))

    if request.user.is_authenticated:
        if level=='member' and not project.member(request.user):
            raise PermissionDenied
        if level=='iadmin' and not project.iadmin(request.user):
            raise PermissionDenied
        if level=='tadmin' and not project.tadmin(request.user):
            raise PermissionDenied
        else:
            return project

    # HTTP basic auth required, check it
    elif 'HTTP_AUTHORIZATION' in request.META:
        authtype, auth = request.META['HTTP_AUTHORIZATION'].split(' ')
        auth = base64.b64decode(auth).decode('utf-8')
        username, password = auth.split(':')

        user = authenticate(username=username, password=password)

        if user is not None:
            if user.is_active:
                django_login(request,user)

                if level=='member' and not project.member(request.user):
                    raise PermissionDenied
                if level=='iadmin' and not project.iadmin(request.user):
                    raise PermissionDenied
                if level=='tadmin' and not project.tadmin(request.user):
                    raise PermissionDenied

                return project

            else:
                log.info('user inactive {}'.format(user))
        else:
            # not usual user. maybe partner?
            try:
                p = auth_partner(request)
                # if we're here, p is partner
                profile = project.owner.profile

                if profile.partner_name != p['name']:
                    # other partner
                    raise PermissionDenied

                if not project.partner_access:
                    # other partner
                    raise PermissionDenied

                return project

            except PermissionDenied:
                pass

            log.info('no such user/pass for username {}'.format(username))

    elif api_key:
        if project.check_api_key(api_key):
            # key is valid, check access level
            if level in ['member', 'iadmin']:
                return project
        raise PermissionDenied
    else:
        log.info('neither authenticated, nor HTTP_AUTHORIZATION')

    raise PermissionDenied


#
# return user email from request
# either request.user.email
# or from HTTP authorization
#
#
def get_user_email(request):
    if request.user.is_authenticated:
        return request.user.email
    elif 'HTTP_AUTHORIZATION' in request.META:
        authtype, auth = request.META['HTTP_AUTHORIZATION'].split(' ')
        auth = base64.b64decode(auth).decode('utf-8')
        username, password = auth.split(':')
        return username
    else:
        return None


#
# True for our trusted IPs
#
def security_check(request, quiet=False):
    # security check. True if okerr host (trusted)
    remoteip = get_remoteip(request)
    reverse = None

    func = sys._getframe(1).f_code.co_name

    if remoteip in settings.TRUSTED_IPS:
        return True

    ipa = IPAddress(remoteip)
    for tn in settings.TRUSTED_NETS:
        subnet = IPNetwork(tn)
        if ipa in subnet:
            return True

    if hasattr(settings, 'TRUSTED_DOMAINS'):
        reverse = get_verified_reverse(remoteip)
        for domain in settings.TRUSTED_DOMAINS:
            if reverse.endswith(domain):
                # trusted by verified reverse
                return True

    if not quiet:
        # warn only about other function
        log.warning("security_check FAIL {} ip: {} rev: {}"
                    .format(func, remoteip, reverse))

    return False


def need_relocate(project):
    return project.ci != myci()


def relocate_url(project):
    #ts = TransactionServer.ciserver(project.ci)
    rs = RemoteServer(ci = project.ci)
    return rs.url

def sredir(request, name, path):

    print("sredir", name, path)

    if name.endswith('.okerr.com'):
        url = urljoin('https://{}/'.format(name), path)
    elif name == 'localhost:8000':
        url = urljoin('http://localhost:8000/', path)
    else:
        try:
            rs = RemoteServer(name = name)
            url = urljoin(rs.url, path)
        except KeyError:
            return HttpResponse('bad cluster name "{}"'.format(name), status=400)

    if request.META['QUERY_STRING']:
        url = url + '?' + request.META['QUERY_STRING']
    return redirect(url)


def seen_motd(request):
    motd = requests.get('http://okerr.com/motd/motd.txt')
    motdsha1 = hashlib.sha1(motd.text.encode('utf-8')).hexdigest()

    seensha1 = request.user.profile.last_motd

    if seensha1 == motdsha1:
        return True

    return False

def afterlife(request):
    if request.POST and 'message' in request.POST:
        mail_admins(
            'User last feedback',
            'Email: {}\nMessages:\n{}\n'.format(request.POST['email'], request.POST['message'])
        )
        return redirect('https://okerr.com/')
    else:
        return render(request, 'okerrui/afterlife.html')

def motd(request, return_url=None):

    if return_url is None:
        return_url = 'okerr:afterlogin'

    if 'continue' in request.POST:
        request.user.profile.last_motd = request.POST['hash']
        request.user.profile.save()

        return redirect(request.POST['return_url'])

    ctx = {}
    # get motd
    motd = requests.get(settings.MOTD_MESSAGE_URL)
    motdsha1 = hashlib.sha1(motd.text.encode('utf-8')).hexdigest()

    ctx['motd'] = motd.text
    ctx['return_url'] = return_url
    ctx['hash'] = motdsha1


    # check if should see motd, return motd page
    return render(request, 'okerrui/motd.html', ctx)

def firstlogin(request, return_url=None):

    if return_url is None:
        return_url = 'okerr:afterlogin'

    if 'continue' in request.POST:
        request.session['seen_firstlogin'] = True
        return redirect(request.POST['return_url'])

    ctx = {}
    # get message
    msg = requests.get(settings.FIRSTLOGIN_MESSAGE_URL)

    ctx['motd'] = msg.text
    ctx['return_url'] = return_url
    print(msg.text)

    # check if should see motd, return motd page
    return render(request, 'okerrui/motd.html', ctx)



def afterlogin(request):

    # sanity check. anon user?
    if not request.user.is_authenticated:
        # anon? not here
        return redirect('okerr:index')

    first_login = (timezone.now() - request.user.date_joined).total_seconds() < 30

    remoteip = get_remoteip(request)

    if first_login and not request.session.get('seen_firstlogin', False) and \
            getattr(settings, 'FIRSTLOGIN_MESSAGE_URL', None):
        return redirect('okerr:firstlogin')

    if getattr(settings, 'MOTD_MESSAGE_URL', None) and request.user.is_authenticated and not seen_motd(request):
        return redirect("okerr:motd")

    if 'afterlogin_redirect' in request.session:
        log.info('{} AFTERLOGIN got url in session: {}'.format(remoteip, request.session['afterlogin_redirect']))
        url = request.session['afterlogin_redirect']
        del request.session['afterlogin_redirect']
        return redirect(url)
    else:
        log.info('{} {} AFTERLOGIN no afterlogin_redirect. skey: {}'.format(remoteip, request.get_host(), request.session.session_key))

    make_tip(request)
    return redirect('okerr:index')

def make_tip(request):
    profile = request.user.profile

    if profile.training_stage is None:
        notify(request, _('You can take quick built-in training to learn Okerr.\n'
                          'Open your Profile (clicking on your email in top-right corner) and start training at any time'))
    elif profile.training_stage != 'basic:DONE':
        notify(request, _('After you will complete training, you will not only learn Okerr,'
                          ' but also will get higher plan as reward (permanently)'))


def relocate(request, project, indicator = None):
    remoteip = get_remoteip(request)

    # log.info('RELOCATE project: {}, indicator: {}'.format(project, indicator))

    if indicator is None:
        # redirect to project
        url = reverse('okerr:pi', kwargs={ 'textid': project.get_textid()})
    else:
        url = reverse('okerr:ilocator', kwargs={'pid': project.get_textid(), 'iid': indicator})

    # log.info('RELOCATE url: {}'.format(url))

    rs = RemoteServer(ci = project.ci)
    land_url = rs.land_url(url, request.META['HTTP_HOST'])

    log.info("RELOCATE {} relocate {} to {}".format(remoteip, request.META['HTTP_HOST'], land_url))

    return redirect(land_url)





# Create your views here.
#@login_required(login_url='myauth:login')
def index(request):

    if request.get_host() in ['cat.okerr.com', 'cat.okerr.com:8000']:
        return cat(request)


    if not request.user.is_authenticated:
        return redirect('myauth:login')

    ctx = dict()

    pm = None

    if not 'onceafterlogin' in request.session:
        # check invites
        request.session['onceafterlogin']=True
        ninv = ProjectInvite.objects.filter(email=request.user.username, left__gt=0).count()
        if ninv>0:
            return redirect('okerr:acceptinvite')

    preferred = request.COOKIES.get('preferred_project', None)
    if preferred:
        project = Project.get_by_textid(preferred)
        pm = ProjectMember.objects.filter(email=request.user.email, project=project, project__deleted_at__isnull = True).first()

    # find project and redirect to pi
    # find any project we're admin
    if pm is None:
        pm = ProjectMember.objects.filter(email=request.user.email, tadmin = True).first()

    # ok, find any project we have access
    if pm is None:
        pm = ProjectMember.objects.filter(email=request.user.email).first()

    if pm is None:
        # no luck...
        ctx['projectlist'] = reverse('okerr:projectlist')
        return render(request, 'okerrui/noproject.html', ctx)

    # here we have pm
    project = pm.project
    textid = project.get_textid()
    return redirect('okerr:pi', textid)

@login_required(login_url='myauth:login')
def pi(request, textid):

    msg = list()

    if not 'onceafterlogin' in request.session:
        # check invites
        request.session['onceafterlogin']=True
        ninv = ProjectInvite.objects.filter(email=request.user.username, left__gt=0).count()
        if ninv>0:
            return redirect('okerr:acceptinvite')

    profile = request.user.profile

    project = Project.get_by_textid(textid)

    if project is None:
        return redirect('okerr:index')

    if project.deleted_at:
        return redirect('okerr:index')

    # check if this user member
    if not project.member(request.user):
        # no access to this user
        return redirect('okerr:index')

    # redirect

    if need_relocate(project):
        try:
            base_url = relocate_url(project)
            if request.COOKIES.get('noredirect',''):
                msg.append(u'noredirect set. do not move to {}'.format(base_url))
            else:
                log.info(u'PI, relocate to project {}'.format(project))
                return relocate(request, project)
        except ObjectDoesNotExist:
            msg.append(u'Sorry, no server for project {}'.format(project))


    if 'danger' in request.session:
        danger = request.session['danger']
    else:
        danger = False

    context = {'profile': profile,'msg': msg, 'pid': project.id, 'project': project, 'danger': danger }

    resp = render(request,'okerrui/index.html',context)

    if 'localhost' in request.META['HTTP_HOST']:
        resp.set_cookie('preferred_project', textid)
    elif 'okerr.com' in request.META['HTTP_HOST']:
        resp.set_cookie('preferred_project', textid, domain='.okerr.com')

    return resp

@login_required(login_url='myauth:login')
def chproject(request):
    textid1 = request.POST.get('textid1')
    textid2 = request.POST.get('textid2')
    path = request.POST.get('path')

    if not textid1 or not textid2:
        return redirect('okerr:index')

    newpath = path.replace(textid1, textid2)
    return redirect(newpath)

@login_required(login_url='myauth:login')
def add(request, tid):

    remoteip = get_remoteip(request)

    msg = []

    create=True
    project = Project.get_by_textid(tid)

    if project is None:
        notify(request, "whaat")
        return redirect('okerr:index')


    if not project.iadmin(request.user):
        notify(request, "sorry, are are not iadmin")
        return redirect('okerr:index')


    if project.iadmin(request.user):
        # check if no indicator with same name in this project
        iname = str(request.POST.get('name',''))

        if len(iname)==0:
            notify(request, _('Cannot create indicator without name'))
            create=False
            return redirect('okerr:index')

        if not Indicator.validname(iname):
            notify(request, _("Bad indicator name"))
            create=False
            return redirect('okerr:index')


        try:
            project.get_indicator(iname)
        except Indicator.DoesNotExist:
            # good, available name
            pass
        except Indicator.MultipleObjectsReturned:
            notify(request, _('Indicator "{}" already exists in project "{}"'\
                .format(iname, project.name)))
            create=False
        else:
            notify(request, _('Indicator "{}" already exists in project "{}"'\
                .format(iname, project.name)))
            create=False

        if not project.owner.profile.can_new_indicator():
            notify(request, _(u'User already hit maxinidicator limit ({}). Indicator not created').format(project.owner.profile.getarg('maxindicators')))
            create=False

        if project.limited:
            notify(request, _(u'This project is limited. Indicator not created').format(project.owner.profile.getarg('maxindicators')))
            create=False



        if create:

            cm = CheckMethod.objects.get(codename='heartbeat')
            i = Indicator()
            i.name = iname
            i.project = project
            i.ci = project.ci
            i.policy = i.project.get_defpolicy() # add view
            i.cm = cm
            i._status='OK'
            i.details='initial value'
            i.reschedule()
            i.save() # save MUST be fore setdefargs, because setdefargs needs i.id
            log.info("UICREATE {} {} ({}) created i#{} '{}'".\
                format(request.user.username,tid,project.name,i.id,iname))

            i.log("created from web UI", typecode="indicator")
            i.alert("created by {} from {}".format(request.user.username, remoteip))
            project.log("{} from {} created {}".format(request.user.username, remoteip, iname))
            i.startmaintenance(request.user) #after save!
            i.setdefargs()
            i.save() # save again.
            return redirect('okerr:ilocator', i.project.get_textid(), i.name)

    else:
        notify(request, _("You dont have permission to manage indicators in project {}").format(project.name))

    return redirect('okerr:index')



@login_required(login_url='myauth:login')
def sendsummary(request, textid):
    ### input validation
    if textid is None:
        return HttpResponse("no pid!",status=500)
    try:
        if request.user.is_authenticated:
            project = Project.get_by_textid(textid)
        if project is None:
            return HttpResponseNotFound('No such project textid (or no access to it)')
    except ObjectDoesNotExist:
        log.error('cannot get project id {} to send summary (requested by {})'.\
            format(textid, request.user.username))
        return HttpResponse("YOU SHALL NOT PASS",status=403)

    if not project.member(request.user):
        log.error("SECURITY user {} wanted to send summary for {} "\
            "({}) owned by user {}".format(request.user.username,project.get_textid(),
            project.name, project.owner.username))
        return HttpResponse("YOU SHALL NOT PASS",status=403)

    desc = request.POST.get("desc","no special description")

    ### work

    if len(desc)>0:
        subj="{}: {}".format(request.user.username,desc)
    else:
        subj="User {} manually requested this summary".format(request.user.username)
    project.sendsummary(subj)

    return HttpResponse("OK",status=200)


@login_required(login_url='myauth:login')
def doop(request, textid):

    remoteip = get_remoteip(request)
    project = Project.get_by_textid(textid)

    project.check_user_access(request.user, 'iadmin')

    cmd=request.POST['masscmd']
#    iid = int(request.POST['iid'])
    i = project.get_indicator(name=request.POST['name'])

    if i.project.iadmin(request.user):
        if cmd == 'maintenance':
            if i.maintenance:
                i.stopmaintenance(request.user)
                i.save()
            else:
                i.startmaintenance(request.user)
                i.save()
        elif cmd == 'retest':
            i.retest()
            i.save()
        elif cmd == 'delete':
            if i.disabled:
                i.log(u'u: {} ip: {} deleted (masscmd)'.format(request.user.username, remoteip), typecode='indicator')
                i.predelete()
                i.delete()
                return HttpResponse('{"deleted": true}', status=200)
            else:
                notify(request,_("Only disabled indicator can be deleted. Indicator {} not disabled.").format(i.name))
                return HttpResponse('{"deleted": false}', status=200)

        elif cmd == 'enable':
            if i.disabled:
                i.log(u'u: {} ip: {} enabled (masscmd)'.format(request.user.username, remoteip), typecode='indicator')
                i.enable()
            else:
                i.log(u'u: {} ip: {} disabled (masscmd)'.format(request.user.username, remoteip), typecode='indicator')
                i.disable()
            i.save()
        elif cmd == 'silent':
            if i.silent:
                i.log(u'u: {} ip: {} set silent flag OFF (masscmd)'.format(request.user.username, remoteip), typecode='indicator')
            else:
                i.log(u'u: {} ip: {} set silent flag ON (masscmd)'.format(request.user.username, remoteip), typecode='indicator')
            i.silent = not i.silent
            i.save()

#        elif cmd=='disable':
#            i.disable()
#            i.save()
        else:
            return HttpResponse("unknown masscmd '{}'".format(request.POST['masscmd']), status=400)

        Indicator.update_tproc_sleep()

        content = json.dumps(i.rawdatastruct(),sort_keys=True,indent=4, separators=(',', ': '))
        return HttpResponse(content, content_type='text/plain')
    else:
        return HttpResponse('not iadmin', status=404)


@login_required(login_url="myauth:login")
def UNUSED_setvpid(request,vpid=None):
    if vpid is not None:
        request.session['vpid']=int(vpid)
    else:
        request.session.pop('vpid',None)
    return redirect('okerr:index')

@login_required(login_url="myauth:login")
def projectlist(request):

    msg=[]

    profile=request.user.profile

    if request.POST.get('add',False):
        name = request.POST.get('name','')
        # get total number of projects
        op = profile.oprojects()
        maxop = profile.getarg('maxprojects')

        if len(op) >= maxop:
            notify(request, 'Can not create new project, already have {} of {} allowed project(s)'.format(len(op),maxop))
        else:
            t = Project.create(name=name,owner=request.user)

    projects=[]
    for t in profile.projects():
        project={}
        project['id']=t.id
        project['name']=t.name
        project['owner']=t.owner
        project['nmembers']=t.nmembers()
        project['stats']=t.stats()
        project['iadmin']=t.iadmin(request.user)
        project['tadmin']=t.tadmin(request.user)
        project['textid']=t.get_textid()


        project['textids']=list(t.projecttextid_set.values_list('textid',flat=True))


        projects.append(project)


    context={'profile':profile,'projects':projects, 'msg':msg}

    return render(request, 'okerrui/projectlist.html',context)


@login_required(login_url="myauth:login")
def project(request, pid):

    remoteip = get_remoteip(request)

    msg=[]

    class UploadFileForm(forms.Form):
        # title = forms.CharField(max_length=50)
        backup = forms.FileField(label=_('Backup file'))

    # prepare default context
    project = Project.get_by_textid(pid)
    if project is None:
        return redirect('okerr:index')

    tadmin = project.tadmin(request.user)
    profile = request.user.profile
    context = {'profile': profile, 'project': project, 'tadmin': tadmin}


    # only project member can view this
    if not project.member(request.user):
        return redirect('okerr:index')


    # only tadmin can POST
    if request.POST:
        if not project.tadmin(request.user):
            context['error_message'] = "you are not project admin, sorry"
            return render(request, 'okerrui/project.html',context)

    cmd = request.POST.get('cmd', False)

    if cmd == 'partner_access_enable':
        project.partner_access = True
        project.save()
        return redirect(request.path)

    if cmd == 'partner_access_disable':
        project.partner_access = False
        project.save()
        return redirect(request.path)


    if cmd == 'newowner':
        newowner = request.POST.get('newowner', '')
        User = get_user_model()
        # is this user member
        u = User.objects.filter(username=newowner).first()
        if u:
            log.info('setnewowner {} changed owned for p:{} "{}" to {}'.format(
                request.user.username,project.id,project.name, newowner))
            project.owner = u
            project.tsave()

            return redirect(request.path)

    if request.POST.get('add_access_key', False):
        suffix = " ({} {})".format(request.user.username, datetime.datetime.now().strftime('%Y/%m/%d'))
        ac = ProjectAccessKey(project = project)
        ac.generate(request.POST['remark'] + suffix)
        ac.save()
        notify(request, _("Copy this key (it will not be displayed in UI):\n")+ac.key)
        project.log("User {} created new API key {} / {}".format(request.user.username, ac.preview(), ac.remark))
        return redirect(request.path)

    if request.POST.get('del_access_key', False):
        id = request.POST.get('id')
        ac = project.projectaccesskey_set.get(id=id)
        notify(request, _("Deleted API key: {} / {}").format(ac.preview(), ac.remark))
        project.log("User {} deleted API key {} / {}".format(request.user.username, ac.preview(), ac.remark))
        ac.delete()
        return redirect(request.path)

    if request.POST.get('addpolicy', False):
        name = request.POST.get('name', '')
        # maybe already exists?
        if project.policy_set.filter(name=name).count():
            notify(request, _('Policy name must be unique'))
            return redirect(request.path)

        try:
            Policy.validname(name)
        except ValueError as e:
            notify(request, str(e))
            return redirect(request.path)

        p = Policy()
        p.retry_schedule = ''
        p.recovery_retry_schedule = ''
        p.name = name
        p.project = project
        p.reduction = '0'
        p.tsave()

        ps = PolicySubnet()
        ps.policy=p
        ps.subnet='0.0.0.0/0'
        ps.remark='IPv4 world access (default)'
        ps.save()

        ps = PolicySubnet()
        ps.policy=p
        ps.subnet='::/0'
        ps.remark='IPv6 world access (default)'
        ps.save()

        return redirect('okerr:policy', project.get_textid(), p.name)


    if request.POST.get('adddyndns', False):
        name = request.POST.get('name','')
        if not name:
            notify(request, _("Name must not be empty"))
            return redirect(request.path)

        if project.dyndnsrecord_set.filter(name=name).count():
            notify(request, 'Already have dynamic DNS for {}'.format(name))
            return redirect(request.path)

        count = project.dyndnsrecord_set.count()
        limit = profile.get_maxdyndns()

        if count >= limit:
            notify(request, 'Already have {}/{} dynamic DNS records'.format(count, limit))
            return redirect(request.path)

        ddr = DynDNSRecord(method = DynDNSRecord.def_method, project = project, name = name)
        ddr.log('created failover scheme {}'.format(name))
        ddr.save()
        return redirect('okerr:dyndns', project.get_textid(), name)



    if request.POST.get('addstatus', False):
        addr = request.POST.get('addr')
        if not addr:
            addr = 'index'

        maxstatus = profile.get_maxstatus()
        cs = project.statuspage_set.count()
        if cs >= maxstatus:
            notify(request, "Already has {} or {} status pages".format(cs, maxstatus))
            return redirect(request.path)

        # check if already exists
        try:
            sp = project.statuspage_set.get(addr=addr)
        except StatusPage.DoesNotExist:
            pass
        else:
            notify(request, "Already have status page {}".format(addr))
            return redirect(request.path)

        # ok, now add
        sp = StatusPage(
            project = project, addr = addr, title = addr,
            public = False, desc = '')

        sp.save()
        project.log(u'user: {} ip: {} created statuspage {}'.format(request.user.username, remoteip, addr))

        return redirect('okerr:statuspage', project.get_textid(), addr)



    if request.POST.get('pmchange', False):
        # alter project member

        email = request.POST.get('email',None)
        pm = ProjectMember.objects.get(project = project, email=email)

        # if this user is project owner - no changes at all
        if pm.email == project.owner.email:
            context['error_message']="cannot modify project owner"
            return render(request, 'okerrui/project.html',context)

        if request.POST.get('iadmin',None):
            pm.iadmin = True
        else:
            pm.iadmin = False

        if request.POST.get('tadmin',None):
            pm.tadmin = True
        else:
            pm.tadmin=False
        pm.tsave()
        return redirect(request.path)


    if request.POST.get('pmdelete',False):

        email = request.POST.get('email',None)
        pm = ProjectMember.objects.get(project = project, email=email)

        # if this user is project owner - no changes at all
        if pm.email == project.owner.email:
            context['error_message']="cannot delete project owner"
            return render(request, 'okerrui/project.html',context)

        pm.delete()
        return redirect(request.path)




    if request.POST.get('change',False):
        name = request.POST.get('name','')
        project.name=name
        project.tsave()
        return redirect(request.path)

    if request.POST.get('addtextid',False):

        canadd = profile.getarg('settextname')
        if canadd:
            textid = request.POST.get('textid',False)
            if textid:
                try:
                    project.addtextid(textid)
                    project.tsave()
                except ValueError as e:
                    notify(request, str(e))
            else:
                notify(request, "No textid given")
        else:
            notify(request, 'You have no permission to set TextIDs')
        return redirect(request.path)

    if request.POST.get('deltextid',False):
        # check, how many textid we have
        ntid = project.projecttextid_set.count()
        dtid=int(request.POST['deltextid'])
        if ntid>=2:
            tid = ProjectTextID.objects.filter(pk=dtid,project=project).first()
            if tid:
                log.info("u: {} p: {} delete textid {} '{}' (total: {})".\
                    format(request.user.username, project.name,
                        request.POST['deltextid'],
                        tid.textid,ntid))
                tid.delete()
            else:
                tid = ProjectTextID.objects.filter(pk=dtid).first()
                if tid:
                    tidline='tid #{} project #{}:{}'.\
                        format(tid.id,tid.project.id,
                            tid.project.name.encode('utf8'))
                else:
                    tidline='tid id: {} (not found at all)'.format(dtid)
                log.info("u: {} p: #{}:'{}' failed to delete textid: {})"\
                    .format(
                        request.user.username, project.id,
                        project.name.encode('utf8'),
                        tidline
                    ))
            return redirect(request.path)


        else:
            msg.append('Cannot delete last TextID')

    if request.POST.get('delproject',False):
        project.predelete()
        project.delete()
        return redirect('okerr:projectlist')

    if request.POST.get('addinvite',False):
        try:
            days = int(request.POST.get('numdays',7))
        except:
            days=7

        if days==0:
            days=7

        try:
            total = int(request.POST.get('total',1))
        except:
            total=None
        if total==0:
            total=None

        expires = timezone.now() + datetime.timedelta(days=days)

        email = request.POST.get('email','')
        if not validate_email(email):
            email=None
        else:
            # email set, total=1
            total=1

        ProjectInvite.create(project,expires,email,total)
        return redirect(request.path)


        if email:
            # send invite TODO !!!
            plaintext = get_template('invite-email.txt')
            htmly     = get_template('invite-email.html')

            subject = 'okerr invitation from {}'.format(request.user)


            d = Context({ 'user': request.user, 'project':project.name, 'regurl': settings.SITEURL+'signup','loginurl':settings.SITEURL+'login'
 })

            text_content = plaintext.render(d)
            html_content = htmly.render(d)

            msg = EmailMultiAlternatives(subject, text_content, settings.FROM, [email])
            msg.attach_alternative(html_content, "text/html")
            msg.send()
            return redirect(request.path)


    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            jsonstr=""
            for chunk in request.FILES['backup'].chunks():
                jsonstr+=chunk
            try:
                struct = json.loads(jsonstr)
                project.restore(struct)

            except ValueError:
                msg.append('invalid json structure')


    upload_file_form = UploadFileForm()


    context={'profile':profile, 'project':project, 'msg':msg, 'tadmin':project.tadmin(request.user), 'backup_upload': upload_file_form }
    return render(request, 'okerrui/project.html',context)



# @login_required(login_url="myauth:login")
def pdsjson(request,textid,iname):

    project = getProjectHTTPAuth(request,textid)

    if not project:
        return HttpResponse('', status=403)

    # check if user is related to project
    if not security_check(request) and not project.member(request.user):
        return HttpResponse('', status=403)

    # check if user is related to project
    if not project.member(request.user):
        return HttpResponse('', status=403)

    i=project.get_indicator(iname)

    content = json.dumps(i.pdatastruct(),sort_keys=True,indent=4, separators=(',', ': '))
    return HttpResponse(content, content_type='text/plain')


#@login_required(login_url="myauth:login")
def pjson(request,pid):

    project = getProjectHTTPAuth(request,pid)

    if not project:
        return HttpResponse('', status=403)

    # check if user is related to project
    if not project.member(request.user):
        return HttpResponse('', status=403)

    content = json.dumps(project.datastruct(), sort_keys=True, indent=4, separators=(',', ': '))
    return HttpResponse(content, content_type='text/plain')



#@login_required(login_url="myauth:login")
def rawpjson(request,tid):

    if not request.user.is_authenticated and not security_check(request):
        return HttpResponse(status=401)

    project = Project.get_by_textid(tid)
    if not project:
        return HttpResponse('', status=403)

    # check if user is related to project
    if not security_check(request, quiet=True) and not project.member(request.user):
        return HttpResponse('', status=401)

    content = json.dumps(project.rawdatastruct(), sort_keys=True,indent=4, separators=(',', ': '))
    return HttpResponse(content, content_type='text/plain')

@login_required(login_url="myauth:login")
def rawijson(request, iid):
    indicator = Indicator.objects.get(pk=iid)

    if not indicator:
        return HttpResponse('', status=403)

    if not indicator.project.member(request.user):
        return HttpResponse('', status=403)

    # check if user is related to project
    if not indicator.project.member(request.user):
        return HttpResponse('', status=403)

    content = json.dumps(indicator.rawdatastruct(),sort_keys=True,indent=4, separators=(',', ': '))
    return HttpResponse(content, content_type='text/plain')



@login_required(login_url="myauth:login")
def acceptinvite(request):

    pi = ProjectInvite.objects.filter(email=request.user.username).all()

    if 'accept' in request.POST:
        for pi in ProjectInvite.objects.filter(email=request.user.username, left__gt=0).all():
            log.info("u: {} ACCEPT: {}".format(request.user.email, pi))
            acc, err = pi.accept(request.user)
            # no need to save now (accept saves if needed)
            #if acc:
            #    pi.save()

        return redirect('okerr:index')

    if 'notaccept' in request.POST:
        return redirect('okerr:index')


    context={'pi': pi }
    return render(request, 'okerrui/acceptinvite.html',context)

@login_required(login_url="myauth:login")
def invitations(request):
    emsg=[]

    if request.POST.get('inviteid',False):
        try:
            pi = ProjectInvite.objects.get(
                pk=request.POST['inviteid'],
                email=request.user.username)
        except ObjectDoesNotExist:
            log.info('u:{} requested wrong (or others) inviteid #{}'\
                .format(request.user.username, request.POST['inviteid']))
            return redirect('okerr:invitations')

        log.info('{} accept {}'.format(request.user.email, pi))
        acc, err = pi.accept(request.user)
        if acc:
            emsg.append('You joined project '+pi.project.name)
        else:
            emsg.append('You failed to join project '+pi.project.name+' : '+err)

    if request.POST.get('code',False):
        acc, err = ProjectInvite.usecode(request.user,request.POST['code'])
        if acc:
            emsg.append(err)
        else:
            emsg.append(err)


    ii = ProjectInvite.objects.filter(email=request.user.username).all()
    context={'invitations': ii, 'msg': emsg}
    return render(request, 'okerrui/invitations.html',context)


def post2obj(x, fields, request, msg):
    changed = {}

    for f, p in fields.items():

        oldval = getattr(x,f)
        newval = request.POST.get(f,None)

        if p['type'] == 'str':
            if oldval != newval:
                changed[f] = newval
            setattr(x, f, request.POST.get(f, ''))
        elif p['type'] == 'int':
            try:
                val = int(request.POST.get(f, ''))
                # min
                if 'min' in p:
                    if val < p['min']:
                        raise ValueError
                if 'max' in p:
                    if val > p['max']:
                        raise ValueError
                # everything fine!
                if oldval != newval:
                    changed[f] = newval
                setattr(x, f, val)
            except ValueError:
                errline = '{} must be integer.'.format(f)
                if 'min' in p:
                    errline += ' min: {}.'.format(p['min'])
                if 'max' in p:
                    errline += ' max: {}.'.format(p['max'])
                msg.append(errline)
        elif p['type'] == 'bool':
            if request.POST.get(f, False):
                if oldval==False:
                    changed[f] = True
                setattr(x, f, True)
            else:
                if oldval:
                    changed[f]=False
                setattr(x, f, False)
        elif p['type'].startswith('fk:'):
            keyname = p['type'].split(':')[1]

            if request.POST.get(f, False):
                kw = dict()
                kw[keyname] = request.POST[f]

                try:
                    v = p['qs'].get(**kw)
                except ObjectDoesNotExist:
                    pass
                else:
                    if oldval != v:
                        changed[f]=v
                    setattr(x, f, v)
    return changed

@login_required(login_url='myauth:login')
def policy(request, textid, pname):

    project = Project.get_by_textid(textid)

    if not project:
        return redirect('okerr:index')

    msg = []
    policy = project.policy_set.filter(name=pname).first()
    if policy is None:
        return redirect('okerr:project', project.get_textid())

    # check if user has right to access it
    if not project.member(request.user):
        # user not in this project!
        return redirect('okerr:index')

    if request.POST and not project.tadmin(request.user):
        log.info('ERRPOLICY post to policy without tadmin {} {}.{}'.\
            format(request.user.username,textid,pname))
        return redirect('okerr:policy',textid,pnams)


    # delete, but not default
    if request.POST.get('delete', False):
        if policy.name == 'Default':
            notify(request, _('Can not delete "Default" policy'))
            return redirect(request.path)
        # only if user is tadmin
        try:
            policy.delete()
        except ProtectedError:
            notify(request, _('Can not delete policy {} because {} indicators ({} ...) are using it'.format(
                policy.name,
                policy.indicator_set.count(),
                policy.indicator_set.first().name
            )))
            return redirect(request.path)
        return redirect('okerr:project', textid)

    if request.POST.get('addsubnet', False):
        # TODO: valid subnet
        subnet = request.POST.get('subnet', '')
        remark = request.POST.get('remark', '')
        try:
            subnet=IPNetwork(subnet)
            # subnet is good if  no exception
            net = PolicySubnet(policy=policy, subnet=subnet, remark=remark)
            net.save()
        except AddrFormatError:
            msg.append('not valid subnet')

    if request.POST.get('delsubnet', False):
        # TODO: security check
        subid = request.POST.get('subid', None)
        PolicySubnet.objects.filter(policy=policy, id=subid).delete()
        return redirect('okerr:policy', textid, pname)


    if request.POST.get('apply',False):

        # VALIDATION
        # change fields, but cannot change name of default policy
        if policy.name != 'Default':
            policy.name = request.POST['name']
        else:
            if policy.name != request.POST['name']:
                notify(request, _('Can not rename "Default" policy'))

        try:
            Policy.validate_retry_schedule(request.POST['retry_schedule'])
            Policy.validate_retry_schedule(request.POST['recovery_retry_schedule'])
            policy.validate_patience(request.POST['patience'])
            policy.validate_period(request.POST['period'])
            policy.validate_reduction(request.POST['reduction'])
        except ValueError as e:
            notify(request, str(e))
            return redirect(request.path)

        minperiod = project.owner.profile.getarg('minperiod')

        fields = {
            'patience': {'type': 'str'},
            'period': {'type': 'str'},
            'secret': {'type': 'str'},
            'retry_schedule': {'type': 'str'},
            'recovery_retry_schedule': {'type': 'str'},
            'reduction': {'type': 'str'},
            'url_statuschange': {'type': 'str'},
            'autocreate': {'type': 'bool'},
            'httpupdate': {'type': 'bool'},
            'smtpupdate': {'type': 'bool'},
       }

        changed = post2obj(policy, fields, request, msg)
        try:
            Policy.validname(policy.name)
        except ValueError as e:
            notify(request, str(e))
            return redirect(request.path)

        policy.touch(True)
        policy.save()
        # cannot redirect to request.path, because name can be changed
        return redirect('okerr:policy', project.get_textid(), policy.name)

        #return redirect('okerr:policy',pid)
    #emsg=None

    # get profile
    #profile = Profile.objects.filter(user=request.user).get()
    #minperiod = profile.getminval('minperiod')

 #   if p.period < minperiod:
 #       emsg="too low period (must be over {})".format(minperiod)

    context = { 'p': policy, 'project': project, 'msg':msg}
    return render(request, 'okerrui/policy.html',context)

@login_required(login_url="myauth:login")
def indicator_ds(request,iid):
    remoteip = get_remoteip(request)
    i=get_object_or_404(Indicator,pk=iid)

    if not i.project.member(request.user):
        return redirect('okerr:index')

    ds = i.datastruct()
    content = json.dumps(ds, sort_keys=True,indent=4, separators=(',', ': '))
    return HttpResponse(content, content_type='text/plain')



@login_required(login_url="myauth:login")
def ilocator(request,pid,iid):
    plist = request.user.profile.projects()

    project = None

    for p in plist:
        for tid in p.projecttextid_set.all():
            if tid.textid == pid:
                project = p

    if not project:
        for p in plist:
            if p.name == pid:
                project = p

    if not project:
        return redirect('okerr:index')

    if need_relocate(project):
        if request.COOKIES.get('noredirect',''):
            pass
        else:
            log.info('ilocator, redirect iid: {}',format(iid))
            return relocate(request, project, iid)

    # Now, look for indicator
    try:
        i = project.get_indicator(iid, deleted=False)
    except ObjectDoesNotExist:
        return redirect('okerr:index')

    #return redirect('okerr:indicator',i.id)
    return indicator(request, i.id)


@login_required(login_url="myauth:login")
def indicator(request,iid):
    remoteip = get_remoteip(request)

    redis = get_redis(settings.OKERR_REDIS_DB)

    i=get_object_or_404(Indicator, pk=iid)
    # !!! make sure it can show only your indicators
    # basic checks - if user can access to this indicator
    if not i.project.member(request.user):
        return redirect('okerr:index')

    if i.deleted_at:
        # already deleted
        return HttpResponseNotFound('No such indicator')

    # now, if user can change anything
    iadmin_commands = ['change', 'changeargs', 'delete', 'settag', 'deltag', 'copy']

    iargs = {}
    for ianame in Indicator.iarglist():
        iargs[ianame] = i.getiarg(request.user, ianame, None)

    if request.POST and not i.project.iadmin(request.user):
        for cmd in iadmin_commands:
            if request.POST.get(cmd,False):
                notify(request, "You dont have iadmin role, sorry.")
                log.info("noiadmin user {} tries to make command {} for" \
                    "indicator {}".format(request.user.username, cmd, i.id))
                return redirect(request.path)

    if request.POST and i.project.limited:
        notify(request, "Project is limited, changes are not applied.")
        return redirect(request.path)

    msg=[]


    logs = LogRecord.objects.select_related().filter(
        project=i.project, indicator=i).order_by('-created')[:200][::-1]
    # logs = []
    checkmethods = CheckMethod.objects.filter(enabled=True).order_by('name')


    uptime = i.uptimes()

    oldcm = i.cm
    #print "fetched i.cm {}".format(i.cm)
    if request.POST:

        #
        # star and subscription
        #
        if request.POST.get('changeiargs',False):
            for ianame in Indicator.iarglist():
                if request.POST.get(ianame,False):
                    i.setiarg(request.user,ianame,True)
                    iargs[ianame]=i.getiarg(request.user,ianame)
                else:
                    i.setiarg(request.user,ianame,False)
                    iargs[ianame]=i.getiarg(request.user,ianame)
            i.save()
            return redirect(request.path)

        if request.POST.get('set_ok',False):
            i.dead = False
            i.register_result('OK','user {}'.format(request.user.username), source="WebUI",
                can_retry=False)
            i.save()
            return_url = request.POST.get('return_url', request.path)
            return redirect(return_url)

        if request.POST.get('set_err',False):
            i.dead = False
            i.register_result('ERR','user {}'.format(request.user.username), source="WebUI",
                can_retry=False)
            i.save()
            return_url = request.POST.get('return_url', request.path)
            return redirect(return_url)


        if request.POST.get('settag',False):
            tagname=request.POST.get('tag','')
            if len(tagname)>0:
                i.log(u'user {} set tag \'{}\''.\
                    format(request.user.username,tagname),
                    typecode="indicator")
                i.settag(tagname)
                i.save()
                return redirect(request.path)

        if request.POST.get('deltag',False):
            tagname=request.POST.get('tag','')
            if len(tagname)>0:
                i.log('user {} deleted tag \'{}\''.\
                    format(request.user.username,tagname),
                    typecode="indicator")
                i.deltag(tagname)
                i.save()
                return redirect(request.path)


        # Change main indicator details
        if request.POST.get('apply', False) or request.POST.get('autosubmit', ''):

            fields = {
                'name': {
                    'type': 'str',
                },
                'desc': {
                    'type': 'str',
                },
                'location': {
                    'type': 'str',
                },
                'disabled': {'type': 'bool'},
                'problem': {'type': 'bool'},
                'silent': {'type': 'bool'},
                'policy': {
                    'type': 'fk:name',
                    'qs': Policy.objects.filter(project=i.project)
                    },
                'cm': {
                    'type': 'fk:codename',
                    'qs': CheckMethod.objects.all()
                    },
            }


            if request.POST['name'] != i.name:
                # can change name only to unique name
                try:
                    i.project.get_indicator(request.POST['name'])
                except Indicator.DoesNotExist:
                    pass
                except Indicator.MultipleObjectsReturned:
                    notify(request,u'indicator {} already exists in this project'.format(request.POST['name']))
                    return redirect(request.path)
                else:
                    notify(request,u'indicator {} already exists in this project'.format(request.POST['name']))
                    return redirect(request.path)

            if Indicator.validname(request.POST.get('name')):
                changed = post2obj(i, fields, request, msg)
            else:
                changed = dict()

            for chi, val in changed.items():
                msg = 'CHANGE_INDICATOR u: {user} ip: {ip} changed {iname}@{textid} {chi} = {val} from web form'\
                    .format(
                        user=request.user.username,
                        ip=remoteip,
                        textid = i.project.get_textid(),
                        iname=i.name,
                        chi=chi,
                        val=val)
                log.info(msg)
                i.log(msg, typecode="indicator")
                i.touch()

            i.fix()  # to fix location


            # change args if cm changed
            #i.tsave()


            # if changed checkmethod, set default args
            if 'cm' in changed.keys():
                i.log("u: {} ip: {} changed cm to {}".format(
                    request.user.username, remoteip,i.cm.name),
                    typecode="indicator")
                i.setdefargs()
                i.dead=False
                i.touch()
                #i.tsave()

            else:

                for argname in i.cm.argnames():
                    newval = request.POST.get(argname,'')
                    newval = Indicator.fixarg(newval)
                    oldval = Indicator.fixarg(i.getarg(argname))

                    if oldval != newval:
                        i.log("u: {} ip: {} Set {}='{}'".format(
                            request.user.username,
                            remoteip,argname,shortstr(newval)
                            ),
                            typecode="indicator")

                        log.info('u: {} changed i: {} arg: {}, old: {} new: {}'\
                            .format(request.user.username, i.name,
                            argname,shortstr(oldval), shortstr(newval)))

                        i.setarg(argname,newval)
                        i.clean_args()
                        #i.touch()
                        i.save()

            # double-check, because maybe we're here because changed cm and autosubmit
            if request.POST.get('apply', False) and i.cm.active():
                i.log('u: {} ip: {} requested retest indicator'.format(request.user.username, remoteip),
                    typecode="indicator")
                i.retest()

            # no touch, maybe just retest
            i.save()
            Indicator.update_tproc_sleep()
            return redirect('okerr:ilocator', i.project.get_textid(), i.name )

        # change options
        # if request.POST.get('changeargs',False):


        if request.POST.get('apply',False):

            for arg in i.cm.checkarg_set.all():
                argname=arg.argname
                newval = request.POST.get(argname,'')
                newval = Indicator.fixarg(newval)
                oldval = Indicator.fixarg(i.getarg(argname))

                if oldval != newval:
                    i.log("u: {} ip: {} Set {}='{}'".format(
                        request.user.username,
                        remoteip,argname,shortstr(newval.encode('utf8'))),
                        typecode="indicator")

                    log.info('u: {} changed i: {} arg: {}, old: {} new: {}'\
                        .format(request.user.username, i.name,
                        argname,shortstr(oldval), shortstr(newval)))

                    i.setarg(argname,newval)
                    i.save()
            return redirect(request.path)


        # maintenance
        if request.POST.get('startmaintenance',False):
            i.startmaintenance(request.user)
            log.info('u: {} i: {} started maintenance'
                .format(request.user.username, i.name))

            i.tsave()
            return redirect(request.path)

        if request.POST.get('stopmaintenance',False):
            i.stopmaintenance(request.user)
            log.info('u: {} i: {} stopped maintenance'
                .format(request.user.username, i.name))
            i.tsave()
            return redirect(request.path)

        # delete
        if request.POST.get('delete',False):
            log.info('u: {} i#{}: {} deleted'
                .format(request.user.username, i.id, i.name))
            #i.set_delete()
            #i.touch()
            #i.save()

            i.project.log('user {} ({}) deleted indicator {}'.format(request.user, remoteip, i.name))
            i.predelete()
            i.delete()
            return redirect('okerr:pi', i.project.get_textid())

        if request.POST.get('retest',False):
            log.warning('u: {} i: {} request retest'
                .format(request.user.username, i.name))
            i.log('u: {} requested retest ASAP'.format(request.user.username))
            i.retest()
            i.tsave()
            return redirect(request.path)

        if request.POST.get('copy',False):
            copyname = str(request.POST.get('copyname','noname'))

            # must not have such indicator
            log.info('u: {} i: {} copy to {}'.format(
                request.user.username, i.name, copyname))
            i.log('u: {} ({}) copied to {}'.format(request.user.username, remoteip, copyname),
                typecode='indicator')
            try:
                copy = i.copy(copyname)
            except ValueError as e:
                notify(request, str(e))
                return redirect(request.path)
            return redirect('okerr:ilocator',i.project.get_textid(),copy.name)



    else:
        # make new form
        pass

    argvals = i.getargs(full=True)

    #iargs={}
    #for ianame in Indicator.iarglist():
    #    iargs[ianame]=i.getiarg(request.user,ianame)

    # keypath section / name

    rkp1 = ''
    rkp2 = ''
    okp1 = ''
    okp2 = ''

    try:
        if i.realkeypath():
            (rkp1, rkp2) = i.realkeypath().split(':', 1)
        else:
            rkp1=''
            rkp2=''

        if i.origkeypath:
            (okp1, okp2) = i.origkeypath.split(':', 1)
        else:
            okp1=''
            okp2=''

    except ValueError:
        log.warn("i#{} {} rkp: {} okp: {}".format(i.id, i.name, i.realkeypath(), i.origkeypath))

    # changes
    changes = list()
    for ic in i.ichange_set.order_by('-created')[:20]:
        s = dict()
        s['created'] = ic.created
        s['old'] = ic.oldstate
        s['new'] = ic.newstate
        changes.append(s)

    old = None
    changes = list(reversed(changes))

    for s in changes:
        if old:
            s['duration'] = s['created'] - old
        else:
            s['duration'] = None

        old = s['created']

    # training part
    if i.name.startswith('test:') and request.user.profile.training_stage is not None and request.user.profile.training_stage != 'DONE':
        tstage = request.user.profile.training_stage
        taskfile = 'okerrui/training/{}/{}.html'.format(get_language(), tstage.split(':')[1])
    else:
        tstage = None
        taskfile = None

    # available sensors
    sensor_list = list()
    sensor_list.append('')

    sl_full = list()
    sl_location = list()
    sl_country = list()

    for k in redis.keys('okerr:sensor:queue:*'):
        qname = k.split(':')[-1]

        if '@' in qname:
            if not qname in sl_full:
                sl_full.append(qname)
        elif '.' in qname:
            if not qname in sl_location:
                sl_location.append(qname)
        else:
            if not qname in sl_country:
                sl_country.append(qname)

    sensor_list.extend(sorted(sl_country))
    sensor_list.append(None)
    sensor_list.extend(sorted(sl_location))
    sensor_list.append(None)
    sensor_list.extend(sorted(sl_full))


        #if qname not in sensor_list:
        #    sensor_list.append(qname)

    # add current location even if not exists
    if i.location not in sensor_list:
        sensor_list.append(i.location)


    context={'i':i,
             'project': i.project,
             'textid': i.project.get_textid(),
             'up': i.upindicator(),
             'lo': i.loindicator(),
             'logs': logs,
             'checkmethods': checkmethods,
             'argvals': argvals,
             'iargs': iargs,
             'uptime': uptime,
             'msg': msg,
             'rkp1': rkp1,
             'rkp2': rkp2,
             'okp1': okp1,
             'okp2': okp2,
             'changes': changes,
             'tstage': tstage,
             'taskfile': taskfile,
             'sensor_list': sensor_list
             }

    resp = render(request,'okerrui/indicator.html',context)
    if 'localhost' in request.META['HTTP_HOST']:
        resp.set_cookie('preferred_project', i.project.get_textid())
    elif 'okerr.com' in request.META['HTTP_HOST']:
        resp.set_cookie('preferred_project', i.project.get_textid(), domain='.okerr.com')

    return resp


@login_required(login_url="myauth:login")
def uptimelog(request, textid, iname):


    project = Project.get_by_textid(textid)
    i = project.get_indicator(iname)

    changes = list()

    old = None
    for ic in i.ichange_set.order_by('created'):
        s = dict()
        s['created'] = ic.created
        s['old'] = ic.oldstate
        s['new'] = ic.newstate
        if old:
            s['duration'] = ic.created - old
        else:
            s['duration'] = None

        changes.append(s)

        old = ic.created

    ctx = {
        'i': i,
        'changes': changes
    }

    return render(request, 'okerrui/uptimelog.html', ctx)


def toggle_interface_level(request, path):
    if request.user.is_authenticated:
        profile = request.user.profile
        profile.set_jarg('full_interface', not profile.get_jarg_full_interface())
        profile.save()

    if not path.startswith('/'):
        path = '/' + path

    return redirect(path)


def eula(request):
    # shows for non-logged in users too
    # only logged in can accept
    msg = []
    context = {'msg': msg}
    context['LANGUAGE_CODE'] = get_language()

    if request.POST:
        cmd = request.POST.get('cmd', '')
        agree = request.POST.get('agree', False)
        if cmd == 'accept_eula':
            if agree:
                profile = request.user.profile
                eulaver = int(SystemVariable.get('eulaver', -1))
                try:
                    pa = ProfileArg.objects.get(profile=profile, name='eulaver_accepted')
                except ObjectDoesNotExist:
                    pa = ProfileArg(name='eulaver_accepted', profile=profile)
                pa.value=eulaver
                pa.save()
                log.info('EULA_ACCEPT u: {} ip: {} eulaver {}'.format(
                    request.user.username,
                    request.META.get('REMOTE_ADDR', '???'),
                    eulaver
                    ))
                return redirect('okerr:index')
            else:
                msg.append('You must accept EULA to use okerr')

    return render(request, 'okerrui/eula.html', context)


@login_required(login_url="myauth:login")
def project_log(request, textid, codelist=None):
    ctx = dict()
    p = Project.get_by_textid(textid)

    if p is None:
        return redirect('okerr:index')

    if not p.member(request.user):
        return redirect('okerr:index')

    if not 'logreverse' in request.session:
        request.session['logreverse'] = False


    # get sort order
    if request.method == 'POST' and 'logreverse' in request.POST:
        # change sort order
        request.session['logreverse'] = not request.session['logreverse']
        return redirect(request.path)

    if not codelist:
        codelist='update'

    if codelist == 'all':
        codelist = ' '.join(LogRecord.typecodes)

    cl = list()
    for code in codelist.split(' '):
        cl.append(LogRecord.get_typecode(code))


    # statistics
    totalcount = p.logrecord_set.filter(typecode__in=cl).count()
    stats = dict()
    for tc in LogRecord.typecodes:
        stats[tc]=0

    for tc in p.logrecord_set.values('typecode').annotate(Count('id')):
        tcname = LogRecord.typecodes[tc['typecode']]
        stats[tcname] = tc['id__count']



    qs = p.logrecord_set.filter(typecode__in=cl).order_by('-created')[:1000]




    ctx['project'] = p
    ctx['codes'] = LogRecord.typecodes
    ctx['totalcount'] = totalcount
    ctx['stats'] = stats
    ctx['count'] = qs.count()
    if request.session['logreverse']:
        ctx['log'] = reversed(qs)
    else:
        ctx['log'] = qs
    ctx['codelist'] = codelist
    ctx['all'] = False

    return render(request, 'okerrui/project_log.html', ctx)



@csrf_exempt
def getpub(request):
    textid = request.POST.get('textid',False)
    name = request.POST.get('name',False)
    argname = request.POST.get('argname',False)
    secret = request.POST.get('secret',False)

    if not (textid and name and argname):
        return HttpResponse('bad getpub request no textid/name/argname',
            status=404)
    try:
        project = Project.objects.get(projecttextid__textid=textid)
    except ObjectDoesNotExist:
        return HttpResponse("getpub: No such project. (textid: '{}')"\
            .format(textid),status=404)
    try:
        i = Indicator.objects.get(project=project,name=name)
    except ObjectDoesNotExist:
        return HttpResponse("getpub: No such indicator {}:{}".\
            format(textid,name),status=404)

    if not argname.startswith('pub:'):
         return HttpResponse("getpub: bad argname '{}', must starts with 'pub:'".\
            format(textid,name),status=403)

    if i.getarg('secret',False):
        # must provide secret
        if not (secret and i.getarg('secret','')==secret):
            return HttpResponse("getpub: requre valid secret",status=403)

    return HttpResponse(i.getarg(argname,''))


@csrf_exempt
# accepts mirroring request
def mirror(request):
    print("got mirror request")
    remoteip = get_remoteip(request)
    if not remoteip in settings.MASTERMIRRORS:
        log.error('reject mirror attempt from {} (not in whitelist)'.format(remoteip))
        return HttpResponseForbidden('bad IP')
    log.info('accept mirroring request from {}'.format(remoteip))


    for field in ['data','hmac','cmd']:
        if not request.POST[field]:
            log.error('reject mirror attempt from {} (no required field {})'.format(remoteip,field))
            return HttpResponseBadRequest('no req field')

    datajson = request.POST['data']
    hmacb64 = request.POST['hmac']
    cmd = request.POST['cmd']

    if cmd=='update':
        reqdata = json.loads(datajson)
        #reqhmac = base64.b64decode(hmacb64)
        mydig = hmac.new(settings.MIRRORSECRET, msg=datajson, digestmod=hashlib.sha256).digest()
        mydigb64 = base64.b64encode(mydig)

        # no hmac.compare_digest in current version
        if hmacb64 != mydigb64:
            log.error('reject mirror attempt from {}, bad digest {}'.format(remoteip,hmacb64))
            return HttpResponseForbidden('bad IP')

        try:
            project = Project.objects.filter(projecttextid__textid=reqdata['project']).get()
        except ObjectDoesNotExist:
            return HttpResponseBadRequest("No such project. (textid: '{}')".format(reqdata['project']))

        idname = reqdata['idname']
        status = reqdata['status']
        details = reqdata.get('details', '')
        secret = reqdata.get('secret', '')
        error = reqdata.get('error', None)
        cmname = reqdata.get('cmname', None)
        clientremoteip = reqdata.get('remoteip', '')

        source = reqdata.get('source', '')

        errstr=Indicator.update(project=project,
            idname=idname,
            status=status,
            details=details,
            secret=secret,
            error=error,
            cmname=cmname,
            source=source,
            remoteip=clientremoteip
            )

    if errstr:
        log.info(u'mirror update {}:{}: {}'.format(
			project.name,idname,errstr))
    else:
        log.info(u'mirror update {}:{} no error'.format(
            project.name,idname))
    return HttpResponse(u'accepted mirror request \'{}\''.format(errstr))



@csrf_exempt
def update(request):


    remoteip = get_remoteip(request)

    for reqfield in ['textid','name','status']:
        if not reqfield in request.POST:
            return HttpResponse("Required field '"+reqfield+"' missing")

    if security_check(request, quiet=True):
        trusted = True
    else:
        trusted = False

    method = request.POST.get('method',None)
    textid = request.POST['textid']

    # get tags from request
    tags = request.POST.get('tags','').split(',')

    # validate tags
    tags = [ tag for tag in tags if re.match('[a-zA-Z0-9_]+',tag) ]

    # now find project by textid
    project = Project.get_by_textid(textid)
    if project is None:
        return HttpResponseNotFound("No such project. (textid: '{}')".format(request.POST['textid']))


    idname = str(request.POST['name'])
    status = str(request.POST['status'])


    source = 'http'
    details = request.POST.get('details', '')
    secret = request.POST.get('secret', '')
    policy = request.POST.get('policy', None)
    error = request.POST.get('error', None)
    keypath = request.POST.get('keypath', '')
    origkeypath = request.POST.get('origkeypath', '')
    desc = request.POST.get('desc', '')

    if trusted:
        if 'x_smtp' in request.POST:
            source = 'smtp'
        if 'x_remoteip' in request.POST:
            remoteip = request.POST.get('x_remoteip',None)

    try:
        errstr=Indicator.update(project=project,
            idname=idname,
            status=status,
            details=details,
            secret=secret,
            error=error,
            cmname=method,
            policy=policy,
            source=source,
            remoteip=remoteip,
            tags=tags,
            keypath=keypath,
            origkeypath=origkeypath,
            desc=desc)

        # calculate update line
        u = "{} {}@{} = {} e:{}".format(remoteip, idname, textid, status, error)

        if secret:
            u += " [secret]"

        if errstr is None:
            log.debug('HTTPUPDATE OK ' + u)
            return HttpResponse("OK", status=200)
        log.info('HTTPUPDATE ERR ({}) {}'.format(errstr, u))
        return HttpResponse(errstr, status=400)
    except OkerrError as e:
        return HttpResponse(str(e), status=400)



@csrf_exempt
def bonusverify(request):
    remoteip = get_remoteip(request)
    email=request.POST.get('email', '')
    bonuscode=request.POST.get('bonuscode', '')
    log.info('BONUSVERIFY {} {} {}'.format(remoteip,bonuscode,email))

    return HttpResponse('0',status=200)

@login_required(login_url="myauth:login")
def tview(request):
    context={}
    return render(request,'invite-email.html',context)

def exportkeyval(request, pid, path):

    p=Project.get_by_textid(pid)
    if p is None:
        return redirect('okerr:index')

    key = p.getkey(path)

    content = json.dumps(key,sort_keys=True,indent=4, separators=(',', ': '))
    return HttpResponse(content, content_type='text/plain')

def exportkeyval_raw(request, pid, path):
    p=Project.get_by_textid(pid)
    if p is None:
        return redirect('okerr:index')

    key = p.getkey_raw(path)

    content = json.dumps(key, sort_keys=True,indent=4, separators=(',', ': '))
    return HttpResponse(content, content_type='text/plain')




# @login_required(login_url="myauth:login")
def getnotifications(request):
    if not 'notifications' in request.session:
        request.session['notifications']=dict()

    content = json.dumps(request.session['notifications'])

    # new: clear notifications immediately once retrieved
    request.session['notifications'] = dict()

    return HttpResponse(content, content_type='application/json')


# @login_required(login_url="myauth:login")
def delnotification(request):

    if request.POST and 'nid' in request.POST:
        nid = request.POST['nid']
    else:
        return HttpResponse("Bad call",status=400)

    if nid in request.session['notifications']:
        del(request.session['notifications'][nid])
        request.session.save()
        return HttpResponse('', status=200)

    return HttpResponse('No such notification id {}'.format(nid), status=404)



def notify(request, msg):
    if not 'notifications' in request.session:
        request.session['notifications']=dict()

    if not 'notifications-counter' in request.session:
        request.session['notifications-counter']=0

    # get unique ID for this notification
    nid = "{}:{}".format('srv',request.session['notifications-counter'])
    request.session['notifications-counter'] = request.session['notifications-counter'] + 1

    request.session['notifications'][nid] = str(msg)


@login_required(login_url="myauth:login")
def updatevkeys(request,pid):
    pid = int(pid)

    try:
        p=Project.objects.get(pk=pid)
    except:
        return redirect('okerr:index')

    if not p.member(request.user):
        return redirect('okerr:index')

    if not p.tadmin(request.user):
        return redirect('okerr:index')


    jk = json.loads(p.jkeys)
    sjk = json.loads(settings.JKEYS_TPL)

    newjk = dict(sjk)

    for keep in ['conf','mylib','servers']:
        if keep in jk:
            newjk[keep] = jk[keep]
        else:
            newjk[keep] = dict()

    p.jkeys = json.dumps(newjk)
    p.save()
    notify(request, 'vendor keys updated')
    # return redirect('okerr:keys',pid,'')
    return getnotifications(request)



@login_required(login_url="myauth:login")
def resetkeys(request,pid):
    pid = int(pid)

    try:
        p=Project.objects.get(pk=pid)
    except:
        return redirect('okerr:index')

    if not p.member(request.user):
        return redirect('okerr:index')

    if not p.tadmin(request.user):
        return redirect('okerr:index')


    sjk = json.loads(settings.JKEYS_TPL)

    newjk = dict(sjk)

    p.jkeys = json.dumps(newjk)
    p.save()
    notify(request, 'keys reset')
    # return redirect('okerr:keys',pid,'')
    return getnotifications(request)




@login_required(login_url="myauth:login")
def keys(request,pid,parentpath=''):

    # fix parentpath. delete trailing ':*' if found
    if parentpath.endswith(':*'):
        parentpath=parentpath[:-2]

    # todo: security

    msg = list()

    p = Project.get_by_textid(pid)

    if p is None:
        return redirect('okerr:index')

    if not p.member(request.user):
        return redirect('okerr:index')


    # do we really need to resolve? I think no. It should be resolved in link
    # parentpath = p.keytree().resolve(parentpath)


    if 'cmd' in request.POST:
        # all commands only for project.iadmins

        if not p.iadmin(request.user):
            return redirect(request.path)


        cmd = request.POST['cmd']
        if cmd=='addkey':

            keyname = request.POST.get('key',None)
            if not keyname:
                return redirect(request.path)

            value = request.POST.get('value','')
            # print "addkey '{}' = '{}'".format(keyname,value)
            try:
                p.addkey(name=keyname,value=value,parentpath=parentpath)
                return redirect(request.path)
            except ValueError:
                msg.append('Bad key. Allowed: letters, numbers, chars from set " -_@:."\nSpace is allowed only for key name "@include <path>" (value: "")')

        if cmd=='addfolder':
            keyname = request.POST.get('name',None)
            if not keyname:
                return redirect(request.path)

            try:
                p.addkey(name=keyname,value=None,parentpath=parentpath)
            except ValueError:
                # bad key name
                pass
            return redirect(request.path)



        if cmd=='delkey':

            patha = request.POST.get('path').split(':')
            patha.append(request.POST.get('name'))

            p.delkey(patha)


        if cmd=='importkeys' and 'json' in request.POST:
            try:
                data = json.loads(request.POST['json'])
                p.addkey(name=None,value=data,parentpath=parentpath)
            except ValueError:
                msg.append(_('Not valid JSON data'))
                pass


    path = []
    pathlink = ''
    # path.append(('root',pathlink))
    for pelem in parentpath.split(':'):
        if pelem:
            if pathlink:
                pathlink += ':'+pelem
            else:
                pathlink = pelem
            path.append((pelem,pathlink))

    pparent = ':'.join(parentpath.split(':')[:-1])

    # subtree from project keytree. and convert to list to reuse
    # because template will walk it twice
    try:
#        keysubtree = sorted(list(p.keytree().treekeys(parentpath)), key=operator.attrgetter('name'))
        #keysubtree = sorted(list(p.keytree().treekeys(parentpath)), key=operator.methodcaller('intname'))
        keylist = list(p.keytree().treekeys(parentpath))

    except KeyError as e:
        # no such key
        return HttpResponseNotFound("<h1>No such key "+parentpath+"</h1>")

    #print("keylist: ",keylist)

    keysubtree = sorted(keylist,key = operator.methodcaller('intname'))

    # treekey = keystruct.key(parentpath)

    #print "keysubtree:",keysubtree
    #print "type:",type(keysubtree)

    context={'project':p, 'path': path, 'ppath': parentpath,
    'msg': msg, 'keysubtree': keysubtree, 'textable': textable(keylist),
    'admin': p.tadmin(request.user) }

    return render(request,'okerrui/keys.html',context)

@csrf_exempt
def getkeyval(request,textid,path):

    # remove any keys with name starting from '@' from data
    def nospecial(data):
        if isinstance(data, str):
            return data
        if isinstance(data,dict):
            out={}
            for k in data:
                if not k.startswith('@'):
                    out[k]=nospecial(data[k])
            return out


    # getkeyval main code

    remoteip = get_remoteip(request)

    try:
        project = Project.objects.get(projecttextid__textid=textid)
    except ObjectDoesNotExist:
        log.info('not found project {}'.format(textid).encode('utf8'))
        return HttpResponseNotFound('no such project')

    if path:
        accesspath=path+":@access"
    else:
        accesspath='@access' # root access
    # print "getting access path {}".format(accesspath)
    access = project.getkey(accesspath)
    if access is not None and len(access):

        noauth = HttpResponse("Auth Required", status=401)
        noauth['WWW-Authenticate'] = 'Basic realm="okerr keys"'

        if not isinstance(access,dict):
            # no auth list, reject anything
            return noauth


        # HTTP basic auth required, check it
        if 'HTTP_AUTHORIZATION' in request.META:
            auth_header = request.META['HTTP_AUTHORIZATION']
            authtype, auth = auth_header.split(' ')
            auth = base64.b64decode(auth).decode('utf-8')
            username, password = auth.split(':')

            # log.info("GETKEYVAL u: {} p: {} ip: {} project: {}".format(username, password, remoteip, textid))
            if not username in access:
                # no such user at all
                return noauth

            goodpass = access[username]
            if len(goodpass) and goodpass!=password:
                log.info("pass mismatch! good: '{}' tried: '{}'".format(goodpass, password))
                return noauth
        else:
            log.info("no auth")
            log.info(request.META)
            return noauth

    else:
        pass
        # print "okay, no @access restrictions"

    # if we're here, we don't need auth or auth valid
    #print "getting keypath {}".format(path)

    # print "try to find path: {} in project p:{} {}".format(path,project.id,project.name)

    key = project.getkey(path)

    # remove anything special from key
    key = nospecial(key)

    resp = HttpResponse(json.dumps(key))
    resp['Client-IP'] = get_remoteip(request)
    return resp


@csrf_exempt
def getkeytree(request,textid,path):
    return HttpResponse('getkeytree')

@csrf_exempt
def getkeylist(request,textid,path):
    return HttpResponse('getkeylist')

def wiznoflap(request, textid, iname):

    project = Project.get_by_textid(textid)
    i = project.get_indicator(name = iname)


    context={}
    msgs=[]

    if not project.member(request.user):
        return redirect('okerr:index')

    if not project.iadmin(request.user):
        return redirect('okerr:indicator',iid)

    if request.POST:
        iname = i.mkupname()
        policy = request.POST.get('policy')
        expr = request.POST.get('expr')
        try:
            okthreshold = int(request.POST.get('okthreshold',0))
        except ValueError:
            okthreshold = 0
        try:
            errthreshold = int(request.POST.get('errthreshold',0))
        except ValueError:
            errthreshold = 0

        expr = "(lo['status']=='OK' and lo['statusage']>{}) or (lo['status']=='ERR' and lo['statusage']<{})".format(okthreshold, errthreshold)

        try:
            up = Indicator.create(i.project, iname, cmname='logic', policy=policy, args={'expr': expr})
        except ValueError as e:
            notify(request, e)
            return redirect(request.path)

        # redirect
        if up:

            if request.POST.get('copytags',False):
                # copy tags
                for tag in i.usertags():
                    if tag not in ['lower-level']:
                        up.settag(tag)

            up.reschedule()
            up.settag('upper-level')
            up.desc = u'Upper-level indicator created by wizard for {}'.format(i.name)
            up.save()

            i.log(u'created upper-level indicator {}'.format(up.name))
            i.settag('lower-level')
            if request.POST.get('silent',False):
                i.silent = True
                i.log(u'wizard set silent flag')
            i.save()

            return redirect('okerr:ilocator',up.project.get_textid(), up.name)
        else:
            msgs.append('Failed to create such indicator')




    context['i']=i
    context['upname']=i.mkupname()
    context['okthreshold']=i.policy.period+i.get_patience()
    context['errthreshold']=i.policy.period*2+i.get_patience()

#    context['expr'] = "(lo['status']=='OK' and lo['statusage']>120) or (lo['status']=='ERR' and lo['statusage']<300)"
    if msgs:
        context['msg']=msgs

    return render(request,'okerrui/wiznoflap.html',context)


@login_required(login_url="myauth:login")
def keystext(request,pid,parentpath=''):

    try:
        p=Project.objects.get(pk=pid)
    except:
        return redirect('okerr:index')

    if not p.member(request.user):
        return redirect('okerr:index')


    # build path structures
    path = []
    pathlink = ''
    for pelem in parentpath.split(':'):
        if pelem:
            if pathlink:
                pathlink += ':'+pelem
            else:
                pathlink = pelem
            path.append((pelem,pathlink))
    pparent = ':'.join(parentpath.split(':')[:-1])




    if 'text' in request.POST:
        text=request.POST['text']

        p.delkey(parentpath+':*')

        lineno=10
        step=10

        for s in text.split('\n'):
            if not s.strip():       # skip empty lines
                continue
            linestr = "%03d" % lineno
            p.addkey(name=linestr, value=s.strip(),parentpath=parentpath)

            lineno += 10

        return redirect('okerr:keys', pid, parentpath)




    try:
        keylist = list(p.keytree().treekeys(parentpath))

    except KeyError as e:
        # no such key
        return HttpResponseNotFound("<h1>No such key "+parentpath+"</h1>")

    if not textable(keylist):
        return HttpResponseNotFound("<h1>No textable key '{}' found (maybe it has subfolders)</h1>".format(parentpath))

    keysubtree = sorted(keylist,key = operator.methodcaller('intname'))

    text=""
    for k in keysubtree:
        # print "k: {} name: {} value: {}".format(k,k.name,k.value)
        text+=k.value+'\n'

    context={'project':p, 'pelem': pelem, 'ppath': parentpath, 'path': path}
    msg=[]

#    text='aa\nbb\ncc'
    context['text']=text

    return render(request, 'okerrui/keystext.html',context)



@login_required(login_url="myauth:login")
def srvedit(request,pid, prepath, path):

    if prepath in ['conf', 'servers']:
        return confedit(request, pid, prepath, path)

    return scriptedit(request, pid, prepath, path)


@login_required(login_url="myauth:login")
def scriptedit(request,pid, prepath, path):
    ctx=dict()

    p = getProjectHTTPAuth(request,pid)


    keys = json.loads(p.jkeys)

    if request.POST.get('save',False):
        if not p.iadmin(request.user):
            return redirect(request.path)


        scr = request.POST.get('script','')
        scrd=dict()

        for i, line in enumerate(scr.split('\n'),start=1):
            num = i*10
            line = line.strip()
            # str index
            num = u'{:04}'.format(num)

            if line:
                scrd[num] = line
        keys[prepath][path] = scrd

        p.jkeys = json.dumps(keys)
        p.tsave()
        return redirect('okerr:servers', p.get_textid())

    if request.POST.get('clone',False):
        if not p.iadmin(request.user):
            return redirect(request.path)


        scr = request.POST.get('script','')
        name = request.POST.get('name','')

        if not name:
            return redirect('okerr:servers', p.get_textid())

        scrd=dict(keys[prepath][path])

        keys['mylib'][name] = scrd

        p.jkeys = json.dumps(keys)
        p.tsave()
        return redirect('okerr:servers', p.get_textid())

    if request.POST.get('delete',False):
        if not p.iadmin(request.user):
            return redirect(request.path)
        del keys[prepath][path]
        p.jkeys = json.dumps(keys)
        p.tsave()
        return redirect('okerr:servers', p.get_textid())


    ctx['project'] = p
    ctx['path'] = prepath+'/'+path

    s = keys[prepath][path]

    script = ''
    for i in sorted(s.keys()):
        script += s[i]+'\n'
    ctx['script'] = script

    if prepath == 'mylib' or 'danger' in request.session :
        ctx['can_delete'] = True
    else:
        ctx['can_delete'] = False

    if p.iadmin(request.user):
        ctx['save']=True
        ctx['disabled']=''
    else:
        ctx['save']=False
        ctx['disabled']='disabled'

    return render(request, 'okerrui/scriptedit.html', ctx)




@login_required(login_url="myauth:login")
def confedit(request, pid, prepath, path):
    ctx=dict()

    p = getProjectHTTPAuth(request,pid)

    # fix path. machine:check -> machine
    path = path.split(':')[0]

    keys = json.loads(p.jkeys)

    if request.POST.get('save',False):

        if not p.iadmin(request.user):
            return redirect(request.path)

        inc = request.POST.get('includes')
        d=dict()
        for i in request.POST.getlist('includes'):
            d["@include "+i]=""

        keys[prepath][path] = d

        p.jkeys = json.dumps(keys)
        p.tsave()
        return redirect('okerr:servers', p.get_textid())


    if request.POST.get('clone',False):
        if not p.iadmin(request.user):
            return redirect(request.path)

        name = request.POST.get('name','')

        if not name:
            return redirect('okerr:servers', p.get_textid())

        # check name
        if not re.match('^[a-zA-Z0-9\-\_]+$', name):
            notify(request, _('Bad syntax'))
            return redirect(request.path)

        scrd=dict(keys[prepath][path])

        keys[prepath][name] = scrd

        p.jkeys = json.dumps(keys)
        p.tsave()
        return redirect('okerr:servers', p.get_textid())


    if request.POST.get('delete',False):
        if not p.iadmin(request.user):
            return redirect(request.path)

        del keys[prepath][path]
        p.jkeys = json.dumps(keys)
        p.tsave()
        return redirect('okerr:servers', p.get_textid())


    ctx['project'] = p
    ctx['path'] = prepath+'/'+path

    ctx['raw'] = keys[prepath][path]

    includes=list()
    enabled=list()


    if prepath != 'conf':
        for k in sorted(keys['conf'].keys()):
            includes.append('conf:'+k)

    for k in sorted(keys['lib'].keys()):
        includes.append('lib:'+k)

    for k in sorted(keys['mylib'].keys()):
        includes.append('mylib:'+k)

    for inc in keys[prepath][path]:
        if inc.startswith('@include '):
            (ati,name) = inc.split(' ')
            enabled.append(name)

    ctx['includes'] = includes
    ctx['enabled'] = enabled


    # print "CONFEDIT. prepath: {} name: {}".format(prepath, name)

    if prepath == 'conf' and path == 'anyserver':
        ctx['can_delete']=False
    else:
        ctx['can_delete']=True

    if p.iadmin(request.user):
        ctx['save']=True
        ctx['disabled']=""
    else:
        ctx['save']=False
        ctx['disabled']="disabled"


    return render(request, 'okerrui/confedit.html', ctx)





@login_required(login_url="myauth:login")
def servers(request,pid):
    ctx=dict()

    p = getProjectHTTPAuth(request,pid)

    remoteip = get_remoteip(request)


    keys = json.loads(p.jkeys)

    if request.POST.get('add',False):
        name = request.POST.get('name')
        password = request.POST.get('pass')
        if not name:
            return redirect(request.path)
        if not '@access' in keys:
            keys['@access']=dict()
        keys['@access'][name] = password
        p.jkeys = json.dumps(keys)
        p.tsave()
        return redirect(request.path)

    if request.POST.get('delete',False):
        client = request.POST.get('client')
        if client in keys['@access'] and p.tadmin(request.user):
            del keys['@access'][client]
            p.jkeys = json.dumps(keys)
            p.tsave()
        return redirect(request.path)

    if request.POST.get('update',False):
        if p.tadmin(request.user):
            log.info('LIBUPDATE {} user {} updates vendor script library'.format(remoteip, request.user.email))
            tpl = json.loads(settings.JKEYS_TPL)
            vlib = tpl['lib']
            keys['lib'] = vlib
            p.jkeys = json.dumps(keys)
            p.save()



    if request.POST.get('create',False):

        name = request.POST.get('name')
        path = request.POST.get('path')

        # check name
        if not re.match('^[a-zA-Z0-9\-\_]+$', name):
            notify(request, _('Bad syntax'))
            return redirect(request.path)


        if (path=='lib' and p.iadmin(request.user) and 'danger' in request.session) \
            or (path in ['mylib','servers','conf'] and p.iadmin(request.user)):
            keys[path][name]=dict()
            p.jkeys = json.dumps(keys)
            p.tsave()
            return redirect('okerr:srvedit', pid=pid, prepath=path, path=name )

        return redirect(request.path)



    ctx['keys'] = keys
    ctx['request'] = request
    ctx['textkeys'] = json.dumps(keys, indent=4)
    ctx['project'] = p

    for section in ['conf','servers','lib','mylib']:
        try:
            ctx[section] = sorted(keys[section].keys())
        except KeyError:
            ctx[section] = dict()

    if p.tadmin(request.user):
        if '@access' in keys:
            ctx['access']=keys['@access']
        else:
            ctx['access']=dict()
        ctx['access_msg'] = ''
    else:
        ctx['access_msg'] = 'You dont have rights to manage this data'

    return render(request,'okerrui/servers.html',ctx)


def getsysvar(request,varname):
    # print "getsysvar",varname
    return HttpResponse(SystemVariable.get(varname,''))


def cat(request):
    ctx = dict()

    nslist = None
    while nslist is None:
        nslist = nsresolve('he.okerr.com', qtype='ns')
        if nslist is None:
            # tmp failure
            time.sleep(1)

    rs = RemoteServer.me()
    ctx['name'] = rs.name
    # ctx['ip'] = socket.gethostbyname(socket.getfqdn())
    ctx['ip'] = settings.MYIP 

    ns = None
    while ns is None:
        nsname = random.choice(nslist)
        ctx['nsname'] = nsname
        try:
            ns = nsresolve(nsname)[0]
        except TypeError:
            # nsresolve returned None
            time.sleep(1)
            pass

    nsip_struct = nsresolve('cat.he.okerr.com', ns)
    if nsip_struct:
        ctx['nsip'] = nsip_struct[0]
    else:
        ctx['nsip'] = '<not resolved>'
    
    now = timezone.now()

    if rs.name in settings.UP_MAP['main']:
        ctx['role'] = 'main'
        if now.minute < 20:
            ctx['status'] = 'OK'
            ctx['left'] = 20 - now.minute
        else:
            ctx['status'] = 'ERR'
            ctx['left'] = 60 - now.minute

    elif rs.name in settings.UP_MAP['backup']:
        ctx['role'] = 'backup'
        if now.minute < 40:
            ctx['status'] = 'OK'
            ctx['left'] = 40 - now.minute
        else:
            ctx['status'] = 'ERR'
            ctx['left'] = 60 - now.minute

    elif rs.name in settings.UP_MAP['sorry']:
        ctx['role'] = 'sorry'
        ctx['status'] = 'OK'
        ctx['left'] = 'never'
    else:
        ctx['role'] = 'unknown'


    ctx['image'] = 'cats/cat-{}.jpg'.format(ctx['role'])
    ctx['hhmm'] = '{:02d}:{:02d}'.format(now.hour, now.minute)

    return render(request, 'okerrui/cat.html', ctx)


######
#
# StatusPage
#
#####



def status(request, textid, addr):
    if not addr:
        addr = 'index'

    remoteip = get_remoteip(request)

    project = Project.get_by_textid(textid)
    if project is None:
        return HttpResponseNotFound()

    if project.ci != myci():
        rs = RemoteServer(ci = project.ci)
        newurl = urljoin(
            rs.url, reverse('okerr:status', kwargs={'textid': textid, 'addr': addr}))

        return redirect(newurl)


    profile = project.owner.profile


    sp = get_object_or_404(StatusPage, project=project, addr=addr)

    if not sp.public:
        # private status pages
        if not request.user.is_authenticated:
            return redirect('myauth:login')
        if not sp.project.member(request.user):
            return redirect('myauth:login')

    if request.POST.get('subscribe', False):
        email = request.POST.get('email')
        plaintext = get_template('statuspage-subscribe.txt')
        htmly     = get_template('statuspage-subscribe.html')

        if not validate_email(email):
            notify(request,_('Invalid email address: "{}"').format(email))
            return redirect(request.path)

        # get limit

        limit = profile.getarg('status_maxsubscribers')
        nsubscribers = sp.statussubscription_set.count()
        if nsubscribers >=limit:
            notify(request, _('Already {} subscribers. Cannot subscribe more. Sorry.').format(nsubscribers))
            return redirect(request.path)

        if sp.is_subscribed(email):
            notify(request, _('Address "{}" already subscribed').format(email))
            return redirect(request.path)
        try:
            th = Throttle.get('statuspage:subscribe:'+email)
        except Throttle.DoesNotExist:
            # good, not throttled
            pass
        else:
            notify(request, _('Already had such request for user {} recently. Try again later').format(email))
            return redirect(request.path)

        Throttle.add('statuspage:subscribe:'+email, priv=None, expires=datetime.timedelta(hours=1))

        d = dict()
        d['sp'] = sp
        d['project'] = project
        d['datecode'], d['code'] = sp.get_code(email, 'subscribe')
        d['email'] = email
        d['hostname'] = settings.HOSTNAME
        d['prefix'] = 'https://cp.okerr.com'
        d['base_url'] = request.build_absolute_uri('/')
        d['hostname'] = settings.HOSTNAME,
        d['MYMAIL_FOOTER'] = settings.MYMAIL_FOOTER

        text_content = plaintext.render(d)
        html_content = htmly.render(d)
        subject = 'Subscribe to {}'.format(sp.title)

        send_email(email, subject=subject, html=html_content, what="status subscribe")

        project.log('email: {} ip: {} requested subscribe to statuspage {}'.format(email, remoteip, addr))
        notify(request, _('Please click on link in confirmational email we sent to {}').format(email))
        return redirect(request.path)

    ctx = dict()
    ctx['sp'] = sp
    ctx['project'] = project
    ctx['chapters'] = sp.get_chapters()

    return render(request, 'okerrui/status.html', ctx)


def jstatus(request, textid, addr):
    if not addr:
        addr = 'index'

    remoteip = get_remoteip(request)

    project = Project.get_by_textid(textid)
    if project is None:
        return HttpResponseNotFound()

    if project.ci != myci():
        rs = RemoteServer(ci=project.ci)
        newurl = urljoin(
            rs.url, reverse('okerr:jstatus', kwargs={'textid': textid, 'addr': addr}))

        redirect_response = HttpResponseRedirect(newurl)
        redirect_response['Access-Control-Allow-Origin'] = '*'
        return redirect_response
        # return redirect(newurl)


    profile = project.owner.profile

    sp = get_object_or_404(StatusPage, project=project, addr=addr)

    if not sp.public:
        # private status pages
        if not request.user.is_authenticated:
            return redirect('myauth:login')
        if not sp.project.member(request.user):
            return redirect('myauth:login')

    content = sp.export()

    content_text = json.dumps(content, sort_keys=True, indent=4, separators=(',', ': '))
    r = HttpResponse(content_text, content_type='application/json')
    if sp.public:
        r['Access-Control-Allow-Origin'] = '*'

    return r

def statusunsubscribe(request, textid, addr, date, code, email):

    remoteip = get_remoteip(request)

    project = Project.get_by_textid(textid)
    if project is None:
        return HttpResponseNotFound()


    if project.ci != myci():
        rs = RemoteServer(ci = project.ci)
        newurl = urljoin(
            rs.url, reverse('okerr:statusunsubscribe',
                kwargs = {'textid': textid, 'addr': addr, 'date': date, 'code': code, 'email': email} ) )

        return redirect(newurl)


    sp = get_object_or_404(StatusPage, project=project, addr=addr)


    try:
        sp.verify_code(date, email, 'unsubscribe', code)
    except ValueError as e:
        notify(request,str(e))
        return redirect('okerr:statuspage', textid, addr)


    if not sp.is_subscribed(email):
        notify(request,_('{} not subscribed'))
        return redirect('okerr:statuspage', textid, addr)


    ss = StatusSubscription.objects.get(status_page = sp, email=email)
    ss.delete()
    project.log(u'email: {} ip: {} unsubscribed from status page {}'.format(
        email, remoteip, sp.addr))

    notify(request,_('You are unsubscribed now'.format(email)))

    return redirect('okerr:status', textid, addr)


def statussubscribe(request, textid, addr, date, code, email):
    print("status subscribe", email)

    remoteip = get_remoteip(request)

    project = Project.get_by_textid(textid)
    if project is None:
        return HttpResponseNotFound()

    if project.ci != myci():
        rs = RemoteServer(ci = project.ci)
        newurl = urljoin(
            rs.url, reverse('okerr:statussubscribe',
                kwargs = {'textid': textid, 'addr': addr, 'date': date, 'code': code, 'email': email} ) )

        return redirect(newurl)


    sp = get_object_or_404(StatusPage, project=project, addr=addr)
    profile = project.owner.profile

    try:
        sp.verify_code(date, email, 'subscribe', code)
    except ValueError as e:
        notify(request, str(e))
        return redirect('okerr:status', textid, addr)


    if sp.is_subscribed(email):
        notify(request, _('{} already subscribed').format(email))
        return redirect('okerr:status', textid, addr)

    limit = profile.getarg('status_maxsubscribers')
    nsubscribers = sp.statussubscription_set.count()
    if nsubscribers >= limit:
        notify(request, _('Already {} subscribers. Cannot subscribe more. Sorry.').format(nsubscribers))
        return redirect('okerr:status', textid, addr)

    ss = StatusSubscription(status_page = sp, email=email, ip=remoteip)
    ss.save()
    project.log('email: {} ip: {} subscribed to status page {}'.format(
        email, remoteip, sp.addr))


    notify(request,_('You are subscribed! You will get message to {} when blog will be updated').format(email))

    return redirect('okerr:status', textid, addr)


@login_required(login_url='myauth:login')
def statuspage(request, textid, addr):

    remoteip = get_remoteip(request)

    project = getProjectHTTPAuth(request, textid)

    sp = get_object_or_404(StatusPage, project=project, addr=addr)

    profile = project.owner.profile
    limit = profile.getarg('status_maxsubscribers')
    nsubscribers = sp.statussubscription_set.count()


    if request.POST.get('delete',False):
        project.log(u'user: {} ip: {} deleted statuspage {}'.format(request.user.username, remoteip, addr))
        sp.delete()
        return redirect('okerr:project',textid)

    if request.POST and request.POST.get('statuspage_edit', False):

        if not project.iadmin(request.user):
            notify(request, "Not indicator admin")
            return redirect(request.path)

        sp.title = request.POST.get('title', '')
        sp.addr = request.POST.get('addr', '')
        sp.desc = request.POST.get('desc', '')
        sp.public = request.POST.get('public', '') == '1'
        sp.can_subscribe = request.POST.get('can_subscribe', '') == '1'
        sp.save()
        return redirect(request.path)

    if request.POST and request.POST.get('newindicator_add', False):

        if not project.iadmin(request.user):
            notify(request, "Not indicator admin")
            return redirect(request.path)

        i = project.get_indicator(request.POST['newindicator'])

        try:
            si = sp.statusindicator_set.get(indicator=i)
        except StatusIndicator.DoesNotExist:
            pass
        else:
            notify(request, "Indicator {} already on this status page".format(i.name))
            return redirect(request.path)


        project.log('user: {} ip: {} added indicator {} to statuspage {}'.format(request.user.username, remoteip, i.name, addr))

        si = StatusIndicator(status_page=sp, indicator=i, title=i.name,
                             weight=1000, chapter=request.POST.get('chapter', ''))
        request.session['statuspage_last_chapter'] = request.POST.get('chapter', '')
        si.save()

        return redirect(request.path)

    if request.POST and request.POST.get('chsi', False):

        if not project.iadmin(request.user):
            notify(request, "Not indicator admin")
            return redirect(request.path)

        si = sp.statusindicator_set.get(indicator__name = request.POST['indicator'])
        si.weight = int(request.POST.get('weight', 0))
        si.title = request.POST.get('title', '')
        si.desc = request.POST.get('desc', '')
        si.chapter = request.POST.get('chapter', '')
        si.details = request.POST.get('details', '') == '1'

        project.log('user: {} ip: {} changed indicator {} in statuspage {}'.format(request.user.username, remoteip, si.indicator.name, addr))
        si.save()

        return redirect(request.path)


    if request.POST and request.POST.get('delsi',False):

        if not project.iadmin(request.user):
            notify(request,"Not indicator admin")
            return redirect(request.path)

        si = sp.statusindicator_set.filter(indicator__name = request.POST['indicator']).first()
        project.log(u'user: {} ip: {} removed indicator {} from statuspage {}'.format(request.user.username, remoteip, si.indicator.name, addr))
        si.delete()

        return redirect(request.path)

    if request.POST and request.POST.get('blogpost',False) and request.POST.get('add',False):

        if not project.iadmin(request.user):
            notify(request, "Not indicator admin")
            return redirect(request.path)

        blog = StatusBlog(status_page = sp, text = request.POST['blogpost'])
        blog.save()
        if sp.can_subscribe:
            blog.send_updates(base_url = request.build_absolute_uri('/'))

        return redirect(request.path)

    if request.POST and request.POST.get('delblog', False):

        if not project.iadmin(request.user):
            notify(request,"Not indicator admin")
            return redirect(request.path)

        blog = sp.statusblog_set.order_by('-created').first()
        blog.delete()
        return redirect(request.path)


    ctx=dict()
    ctx['sp'] = sp
    ctx['maxsubscribers'] = limit
    ctx['nsubscribers'] = nsubscribers
    ctx['project'] = project
    ctx['chapters'] = sp.get_chapters()
    ctx['blogrecord'] = sp.statusblog_set.order_by('-created').first()
    ctx['draft'] = request.POST.get('blogpost','')
    ctx['now'] = timezone.now()
    ctx['last_chapter'] = request.session.get('statuspage_last_chapter', '')
    return render(request, 'okerrui/statuspage.html', ctx)




######
#
# Dynamic DNS
#
#####

@login_required(login_url='myauth:login')
def dyndns(request, textid, name):

    public_ns = [
        ('google-public-dns-b.google.com', '8.8.8.8'),
        ('resolver1.opendns.com.', '208.67.222.222'),
        ('dns.yandex.ru', '77.88.8.8'),
        ('one.one.one.one', '1.1.1.1')
    ]

    p = Project.get_by_textid(textid)

    if p is None:
        raise PermissionDenied

    p.check_user_access(request.user, 'tadmin')

    try:
        ddr = p.dyndnsrecord_set.filter(name=name).first()
    except DynDNSRecord.DoesNotExist:
        return redirect('okerr:project', p.get_textid())

    if ddr is None:
        return redirect('okerr:project', p.get_textid())

    if request.POST.get('method', None):
        method = request.POST.get('method', None)
        ddr.method = method
        ddr.login = None
        # ddr.hostname = 'www' # do not change hostname
        ddr.domain = None
        ddr.secret = None
        ddr.save()
        ddr.log('Configured method: {}'.format(method))
        return redirect(request.path)

    if 'rename' in request.POST:
        ddr.name = request.POST.get('new_name', 'noname')
        ddr.save()
        return redirect('okerr:dyndns', p.get_textid(), ddr.name)

    if 'configure' in request.POST:

        ddr.set_fields(request.POST)
        ddr.save()
        ddr.log('saved new config')
        return redirect('okerr:dyndns', p.get_textid(), ddr.name)

    if 'push' in request.POST:
        # push
        ddr.set_value(force=True)
        if ddr.curvalue:
            ddr.save()
            ddr.log('Set flag to set value to DNS')
        else:
            notify(request, _("No current value for DNS record"))
        # ddr.push_value()
        return redirect(request.path)

    if 'addvalue' in request.POST:
        host = request.POST.get('host','')
        value = request.POST.get('value','')
        priority = request.POST.get('priority','')
        indicator = request.POST.get('indicator','')
        if not host:
            return redirect(request.path)

        try:
            i = p.indicator_set.get(name=indicator)
        except Indicator.DoesNotExist:
            return redirect(request.path)

        try:
            ddr = p.dyndnsrecord_set.get(hostname=host)
        except DynDNSRecord.DoesNotExist:
            return redirect(request.path)

        try:
            socket.inet_aton(value)
        except socket.error:
            notify(request, _("Invalid IP address"))
            return redirect(request.path)

        if ddr.dyndnsrecordvalue_set.filter(indicator = i).count():
            notify(request, _("Already has this indicator in this record"))
            return redirect(request.path)

        if ddr.dyndnsrecordvalue_set.filter(priority = priority).count():
            notify(request, _("Already has this priority in this record"))
            return redirect(request.path)

        ddrv = DynDNSRecordValue(ddr = ddr, indicator = i, priority = priority, value=value)
        ddrv.save()
        ddr.log("added indicator {} pri: {} value: {}".format(i, priority, value))

        return redirect(request.path)


    if request.POST.get('delvalue',False):
        name = request.POST.get('name','')

        try:
            ddrv = ddr.dyndnsrecordvalue_set.get(indicator__name=name)
        except DynDNSRecordValue.DoesNotExist:
            print("not found",name)
            return redirect(request.path)
        print("delete", ddrv)
        ddrv.delete()
        #ddrv.delete()
        return redirect(request.path)



    if 'delete' in request.POST:        
        ddr.delete()
        return redirect('okerr:project', p.get_textid())


    ctx = dict()
    ctx['textid'] = textid
    ctx['project'] = p
    ctx['ddr'] = ddr

    # status JSON?
    try:
        data = json.loads(ddr.status)
        ctx['status'] = json.dumps(data, indent=4, sort_keys=True)
        ctx['status_json'] = True
    except (ValueError, TypeError):
        ctx['status'] = ddr.status
        ctx['status_json'] = False



    # resolve DNS
    ctx['nsdomain'] = list()
    ctx['nspublic'] = list()

    if ddr.status_age()[0] == 'synced':
        if ddr.get_domain():
            nses = nsresolve(ddr.get_domain(),qtype='NS')
            if nses:
                for ns in nses:
                    nsip = nsresolve(ns)
                    r = nsresolve(ddr.fqdn(), nsip[0])
                    if isinstance(r, list) and len(r)==1:
                        ctx['nsdomain'].append((ns, r[0]))
                    else:
                        ctx['nsdomain'].append((ns, r))

        for ns in public_ns:
            name = ns[0]
            value = nsresolve(ddr.fqdn(), ns[1])
            if isinstance(value, list) and len(value) == 1:
                value = value[0]
            ctx['nspublic'].append((name,value))

    ctx['log'] = ddr.logrecords()
    return render(request, 'okerrui/dyndns.html', ctx)



######
#
# API
#
#####

def get_who(request):
    if request.user.is_authenticated:
        return request.user.username

    if 'HTTP_AUTHORIZATION' in request.META:
        authtype, auth = request.META['HTTP_AUTHORIZATION'].split(' ')
        auth = base64.b64decode(auth).decode('utf-8')
        username, password = auth.split(':')
        return username


def api_checkmethods(request):
    c = CheckMethod.getCheckMethods()
    content = json.dumps(c,sort_keys=True, indent=4, separators=(',', ': '))
    return HttpResponse(content, content_type='text/plain')


@csrf_exempt
def api_delete(request, pid, iname):

    remoteip = get_remoteip(request)

    if request.method != 'POST':
        return HttpResponse('Must be HTTP POST request\n', status=400)

    p = getProjectHTTPAuth(request,pid,'iadmin')

    who = get_who(request)

    if need_relocate(p):
        return relocate(request, p, mkticket=False)

    try:
        i = p.get_indicator(iname)
    except Indicator.DoesNotExist:
        return HttpResponseNotFound("Project {} has no indicator {}\n".format(p.get_textid(), iname))
    #i.set_delete()
    #i.tsave()
    i.log(u'deleted via API user {} from IP: {}'.format(who, remoteip))
    i.predelete()
    i.delete()
    return HttpResponse("Deleted indicator {} from project {}\n".format(iname, p.get_textid()))


@csrf_exempt
def api_create(request,pid,iname):

    remoteip = get_remoteip(request)

    p = getProjectHTTPAuth(request,pid,'iadmin')

    if need_relocate(p):
        return relocate(request, p, mkticket=False)


    if request.method != 'POST':
        return HttpResponse('Must be HTTP POST request', status=400)

    who = get_who(request)

    try:
        i = Indicator.create(p, iname)
        i.mtime = timezone.now()
        i.startmaintenance()
        i.tsave()
        i.log(u'created via API {} from IP: {}'.format(who, remoteip))
        log.info("APICREATE {} {} ({}) created i#{} '{}'".format(
            who, pid, p.name, i.id, i.name))
        return HttpResponse("Created {}\n".format(i))
    except ValueError as e:
        return HttpResponse(str(e)+'\n', status=400, content_type='text/plain; charset=utf-8')


def api_indicators(request,pid):
    p = getProjectHTTPAuth(request, pid)

    if need_relocate(p):
        return relocate(request, p)

    ilist=[]
    for i in p.indicator_set.filter(deleted_at__isnull=True).all():
        ilist.append(str(i.name)+'\n')

    return HttpResponse(''.join(ilist), content_type='text/plain; charset=utf-8')


@csrf_exempt
@require_http_methods(["POST"])
def api_recheck(request, pid):

    if not security_check(request):
        log.warning("security check failed, remoteip: {}".format(remoteip))
        return HttpResponse(status=401)

    project = Project.get_by_textid(pid)
    if project is None:
        return HttpResponseNotFound("No such project. (textid: '{}')".format(request.POST['textid']))

    out = project.recheck()

    return HttpResponse(json.dumps(out, indent=4, separators=(',',': '), sort_keys=True), content_type='application/json')


def api_prefix(request,pid,prefix):
    """
        API: get indicators by name prefix
    """
    p = getProjectHTTPAuth(request,pid)

    if need_relocate(p):
        return relocate(request, p, mkticket=False)

    ilist=[]

    for i in p.indicator_set.filter(deleted_at__isnull=True, name__startswith=prefix).all():
        ilist.append(str(i.name)+'\n')

    return HttpResponse(''.join(ilist), content_type='text/plain; charset=utf-8')


def api_filter(request,pid,kvlist):

    p = getProjectHTTPAuth(request,pid)

    if need_relocate(p):
        return relocate(request, p, mkticket=False)

    kvd = dict()
    for kv in kvlist.split('/'):
        if not kv:
            continue
        if '=' in kv:
            k, v = kv.split('=',1)
            kvd[k] = v
        else:
            if kv.startswith('-') or kv.startswith('!'):
                kvd[kv[1:]] = False
            else:
                kvd[kv] = True

    ilist=[]
    for i in p.indicator_set.all():
        if i.filter(kvd):
            ilist.append(str(i.name)+'\n')
    return HttpResponse(''.join(ilist), content_type='text/plain; charset=utf-8')


def api_tagfilter(request,pid,tagline):

    p = getProjectHTTPAuth(request,pid)

    if need_relocate(p):
        return relocate(request, p, mkticket=False)

    tags={}
    lexer = shlex.shlex(tagline)
    lexer.whitespace='/'
    lexer.whitespace_split=True
    for token in lexer:

        if token.startswith('-'):
            tagname = token[1:]
            tagvalue = '-'
        elif token.startswith('+'):
            tagname = token[1:]
            tagvalue = '+'
        else:
            tagname = token
            tagvalue = '+'

        tags[tagname]=tagvalue

    ilist=[]
    for i in p.indicator_set.all():
        if i.tagfilter(tags):
            ilist.append(str(i.name)+'\n')
    return HttpResponse(''.join(ilist), content_type='text/plain; charset=utf-8')


def api_updatelog(request,pid,iid):
    p = getProjectHTTPAuth(request,pid)
    data=list()

    if need_relocate(p):
        return relocate(request, p, mkticket=False)

    try:
        i = p.get_indicator(iid, deleted=False)
    except ObjectDoesNotExist:
        return HttpResponseNotFound("No indicator with id {} in project with textid {}".format(iid, pid))

    for up in i.updatelog_set.all():
        u = dict()
        u['t'] = up.created.strftime('%Y-%m-%d %H:%M:%S')
        u['y'] = up.value
        data.append(u)

    return HttpResponse(json.dumps(data, indent=4), content_type='application/json')


def api_indicator(request,pid,iid):

    p = getProjectHTTPAuth(request,pid)

    if need_relocate(p):
        return relocate(request, p, mkticket=False)

    try:
        i = p.get_indicator(iid, deleted=False)
    except ObjectDoesNotExist:
        return HttpResponseNotFound("No indicator with id {} in project with textid {}".format(iid, pid))

    idata = i.fullDataStruct()

    idata['policyname']=i.policy.name
    idata['policyperiod']=i.policy.period
    idata['checkmethod']=i.cm.codename

    out = json.dumps(idata,sort_keys=True,indent=4, separators=(',', ': '))

    return HttpResponse(out+'\n', content_type='text/plain; charset=utf-8')




def api_get(request,pid,iid,argname):

    p = getProjectHTTPAuth(request,pid,'iadmin')

    if need_relocate(p):
        return relocate(request, p, mkticket=False)

    try:
        i = p.get_indicator(iid, deleted=False)
    except ObjectDoesNotExist:
        return HttpResponseNotFound("No indicator with id {} in project with textid {}".format(iid, pid))


    if argname in ['policy']:
        return HttpResponse(i.policy.name + '\n', content_type='text/plain; charset=utf-8')

    if argname in ['cm','checkmethod']:
        return HttpResponse(i.cm.codename + '\n', content_type='text/plain; charset=utf-8')

    if argname in ['desc']:
        return HttpResponse(getattr(i, argname) + '\n', content_type='text/plain; charset=utf-8')

    if argname in ['silent','problem', 'disabled']:
        return HttpResponse(str(getattr(i, argname)) + '\n', content_type='text/plain; charset=utf-8')


    argval = i.getarg(argname)
    if argval is None:
        return HttpResponseNotFound("Indicator {} with id {} has no arg '{}'".format(i.name,i.id, argname))

    return HttpResponse(argval+'\n', content_type='text/plain; charset=utf-8')

@csrf_exempt
def api_set(request,pid,iid):
    """
        Set all indicator attributes (both optional, such as policy and generic, such as url or patience)
    """
    changed=dict()

    p = getProjectHTTPAuth(request,pid,'iadmin')

    if need_relocate(p):
        return relocate(request, p, mkticket=False)

    try:
        i = p.get_indicator(iid, deleted=False)
    except Indicator.DoesNotExist:
        return HttpResponseNotFound("No such indicator\n")


    if 'policy'in request.POST:
        pname = request.POST['policy']
        try:
            policy = Policy.objects.get(project=p, name=pname)
        except Policy.DoesNotExist:
            return HttpResponseNotFound("No such policy\n")

        i.policy = policy
        changed['policy']=pname
        i.touch()

    if 'description' in request.POST or 'desc' in request.POST:
        desc = request.POST.get('description', request.POST.get('desc'))

        i.desc = desc
        changed['description'] = desc
        i.touch()

    if 'location' in request.POST:
        location = request.POST.get('location', '')
        i.location = location

        changed['location'] = location
        i.touch()


    if 'checkmethod'in request.POST:
        cmname = request.POST['checkmethod']
        try:
            cm = CheckMethod.objects.get(codename=cmname)
        except CheckMethod.DoesNotExist:
            return HttpResponseNotFound("No such policy\n")

        i.cm = cm
        i.dead = False
        i.setdefargs()
        i.touch()
        changed['checkmethod'] = cmname

    for bname in ['silent','disabled','problem']:
        if bname in request.POST:
            sval = request.POST.get(bname)
            try:
                ival = int(sval)
            except ValueError:
                return HttpResponseNotFound("{} can be only 0 or 1\n".format(bname))
            if ival==0:
                bval = False
            else:
                bval = True
            setattr(i,bname,bval)
            changed[bname] = bval
            i.touch()

    if 'retest' in request.POST:
        log.info(u'API retest {}'.format(i.name))
        i.retest()
        changed['retest']=1

    if 'maintenance' in request.POST:
        sval = request.POST.get('maintenance')
        try:
            ival = int(sval)
        except ValueError:
            return HttpResponseNotFound("maintenance can be only 0 or 1".format(bname))
        if ival==0:
            i.stopmaintenance(request.user)
            changed['maintenance'] = False
        else:
            bval = True
            i.startmaintenance(request.user)
            changed['maintenance'] = True
        i.touch()

    for argname, argval in request.POST.items():
        val = i.setarg(argname, argval)
        if val is not None:
            changed[argname] = val
    i.tsave()
    return HttpResponse("Changed {} {}\n".format(i.name, changed), content_type='text/plain; charset=utf-8')


#
# /api/director/mytextid
# /api/director/myname@example.com
# /api/director/p:partner_id
#

def api_director(request, textid):

    if '@' in textid:
        # this is user email, not textid
        try:
            profile = Profile.objects.get(user__email=textid)
        except:
            return HttpResponseNotFound()
        ci = profile.ci
    elif textid.startswith('p:'):
        # partner id, e.g.: #123 check partner_name
        prefix, partner_id = textid.split(':', 1)
        p = auth_partner(request)
        try:
            profile = Profile.objects.get(partner_name=p['name'], partner_id=partner_id)
        except:
            return HttpResponseNotFound()
        ci = profile.ci

    else:
        project = Project.get_by_textid(textid)
        if project is None:
            return HttpResponseNotFound()
        ci = project.ci

    # mname = settings.CLUSTER[p.ci]
    #srv = TransactionServer.ciserver(ci)
    rs = RemoteServer(ci = ci)

    resp =  HttpResponse(rs.url+'\n', content_type='text/plain')
    resp['Client-IP'] = get_remoteip(request)
    return resp

def api_check_version(request, product, version):

    def ver_lt(ver1,ver2):
        for n1,n2 in zip(ver1,ver2):
            n1n = int(n1)
            n2n = int(n2)
            if n1n<n2n:
                return True
        return False

    latest = "2.0.118"   # latest version
    upgrade = "2.0.118"  # major upgrade version

    latest_l = latest.split('.')
    upgrade_l = upgrade.split('.')

    out = dict()
    out['latest']=latest
    ver = version.split('.')

    if product == "okerrclient":

        if ver_lt(ver, upgrade_l):
            out['status']='ERR'
            out['details'] = '{} upgrade REQUIRED to {}'.format(version, latest)

        elif ver_lt(ver, latest_l):
            out['status'] = 'OK'
            out['details'] = '{} upgrade recommended (not required) to {}'.format(version, latest)

        else:
            out['status'] = 'OK'
            out['details'] = '{} latest known version'.format(version)

    else:
        out['status'] = 'ERR'
        out['details'] = 'unknown product "{}"'.format(product)

    return HttpResponse(json.dumps(out, indent=4, sort_keys=True, separators=(',', ': ')), content_type='text/plain')



#
#
# Partner part of API
#
#


def auth_partner(request):
    if not 'HTTP_AUTHORIZATION' in request.META:
        raise PermissionDenied

    authtype, auth = request.META['HTTP_AUTHORIZATION'].split(' ')
    auth = base64.b64decode(auth).decode('utf-8')
    username, password = auth.split(':')
    sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest()

    for p in settings.PARTNERS:
        if username == p['name'] and sha1pass == p['pass']:
            return p
    raise PermissionDenied


def create_user(email, partner_name=None, partner_id=None, partner_access=False):
    # check if user exists
    User = get_user_model()

    user = User.objects.filter(email = email).first()
    if user:
        raise ValueError('User {} already exists'.format(email))

    profile = Profile.objects.filter(partner_name=partner_name, partner_id=partner_id).first()
    if profile:
        raise ValueError('User {}:{} already exists'.format(partner_name, partner_id))



    password = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(10))
    user = User.objects.create_user(email, email, password)
    profile = Profile(user=user)
    profile.partner_name = partner_name
    profile.partner_id = partner_id
    profile.save()
    profile.inits(partner_access = partner_access)


    return password


@csrf_exempt
def api_partner_create(request):
    partner = auth_partner(request)
    remoteip = get_remoteip(request)

    email = request.POST.get('email',None)
    partner_id = request.POST.get('partner_id',None)
    # template = request.POST.get('template',None)

    if not validate_email(email):
        return HttpResponse("Invalid email {}".format(email), status=400, content_type='text/plain; charset=utf-8')


    if not partner['create']:
        return HttpResponse('No right to CREATE', status=401)


    if not (email and partner_id):
        return HttpResponse('Bad format', status=400)

    try:
        password = create_user(email, partner_name = partner['name'], partner_id = partner_id, partner_access=True)
    except ValueError as e:
        return HttpResponse(str(e)+'\n', status=400, content_type='text/plain; charset=utf-8')


    user = Profile.find_user(email)
    user.profile.assign(group = 'Space', time = datetime.timedelta(days=31))


#    if template is not None and template in settings.PROJECT_TEMPLATES:
#        tpl = settings.PROJECT_TEMPLATES[template]
#        p = Project.objects.get(owner__email = email)
#        for i in tpl:
#            upd = Indicator.update(p,i,cmname=tpl[i], details="init from template", tags=['demo'])

    logmsg = 'APIP_C {} partner {} created user {} email: {} '.format(remoteip, partner['name'], partner_id, email)
    log.info(logmsg)
    logger.log(logmsg, kind='partner')


    # get my rs record
    rs = RemoteServer(name = settings.HOSTNAME)

    if rs.is_net():
        for rrs in rs.all_other():
            rrs.force_sync(email)
    else:
        log.info('skip sync all, because myself not networked')


    return HttpResponse(password+'\n')



def api_partner_list(request):
    partner = auth_partner(request)

    out = list()

    for p in Profile.objects.filter(partner_name = partner['name'], ):
        u = dict()
        u['username'] = p.user.username
        u['email'] = p.user.email
        u['partner_name'] = p.partner_name
        u['partner_id'] = p.partner_id
        out.append(u)

    return HttpResponse(json.dumps(out, indent = 4, sort_keys = True,  separators=(',', ': '))+'\n')


def api_partner_check(request, partner_id):
    partner = auth_partner(request)

    out = dict()

    profile = Profile.objects.filter(partner_name = partner['name'], partner_id = partner_id).first()
    if not profile:
        return HttpResponseNotFound('No such user {}:{}'.format(partner['name'], partner_id))

    # srv = TransactionServer.ciserver(profile.ci)
    rs = RemoteServer(ci = profile.ci)

    out['server'] = rs.url
    out['email'] = profile.user.email


    out['membership'] = list()
    for m in profile.membership_set.all():
        md = dict()
        md['group'] = m.groupname
        if m.expires is None:
            md['exp'] = None
            md['exp_unixtime'] = None
        else:
            md['exp'] = m.expires.strftime('%Y%m%d')
            md['exp_unixtime'] = dt2unixtime(m.expires)
        out['membership'].append(md)

    out['projects'] = list()
    for project in Project.objects.filter( owner = profile.user ):
        if not project.partner_access:
            continue

        pinfo = dict()
        pinfo['name'] = project.name
        pinfo['textid'] = project.get_textid()
        pinfo['sum'] = dict()
        pinfo['err'] = list()

        for i in project.indicator_set.all():
            s = i.okerrm()
            if not s in pinfo['sum']:
                pinfo['sum'][s] = 1
            else:
                pinfo['sum'][s] += 1

            if s == 'ERR':
                pinfo['err'].append(i.name)
        out['projects'].append(pinfo)


    return HttpResponse(json.dumps(out, indent = 4, sort_keys = True,  separators=(',', ': '))+'\n')


@csrf_exempt
def api_partner_grant(request):
    partner = auth_partner(request)
    remoteip = get_remoteip(request)
    partner_id = request.POST.get('partner_id',None)
    group = request.POST.get('group',None)
    new = int(request.POST.get('new', '0'))


    if not (partner and partner_id and group):
        return HttpResponse(status=400)

    if not partner['grant']:
        return HttpResponse('No right to GRANT', status=401)

    profile = Profile.objects.filter(partner_name = partner['name'], partner_id = partner_id).first()
    if not profile:
        return HttpResponseNotFound('No such user {}:{}'.format(partner['name'], partner_id))

    if new:
        profile.assign(group = group, time = datetime.timedelta(days=30), force_assign=True)
    else:
        profile.assign(group = group, time = datetime.timedelta(days=30))

    logmsg = 'APIP_G {} granted {} new: {} to {}:{}'.format(remoteip, group, new, partner['name'], partner_id)
    log.info(logmsg)
    logger.log(logmsg, kind='partner')


    return HttpResponse('Granted {} to user {}:{}\n'.format(group, partner['name'], partner_id))


@csrf_exempt
def api_partner_revoke(request):
    partner = auth_partner(request)
    remoteip = get_remoteip(request)
    partner_id = request.POST.get('partner_id',None)
    group = request.POST.get('group',None)
    exp = request.POST.get('exp',None)

    if exp == 'None':
        exp = None

    if not (partner and partner_id and group):
        log.info('ERR revoke partner: {} partner_id: {} group: {}'.format(
            repr(partner), repr(partner_id), repr(group)
            ))
        return HttpResponse(status=400)

    if not partner['revoke']:
        return HttpResponse('No right to REVOKE', status=401)

    profile = Profile.objects.filter(partner_name = partner['name'], partner_id = partner_id).first()
    if not profile:
        return HttpResponseNotFound('No such user {}:{}'.format(partner['name'], partner_id))

    for m in profile.membership_set.filter(group__name=group):
        if (m.expires is None and exp is None) or (m.expires.strftime('%Y%m%d') == exp):
            m.delete()
            logmsg = 'APIP_R {} revoked {} exp: {} from {}:{}'.format(remoteip, group, repr(exp), partner['name'], partner_id)
            log.info(logmsg)
            logger.log(logmsg, kind='partner')


            return HttpResponse('Revoked {} from user {}:{}\n'.format(group, partner['name'], partner_id))

    return HttpResponse('NOT Revoked {} from user {}:{}\n'.format(group, partner['name'], partner_id))





#
#
# Admin part of API
#
#


def api_profile(request, pid):

    if not security_check(request):
        return HttpResponse(status=401)

    profile = None

    try:
        profile = Profile.objects.get(rid = pid)

    except Profile.DoesNotExist:
        pass

    if profile is None:
        try:
            profile = Profile.objects.get(user__email = pid)
        except Profile.DoesNotExist:
            pass

    if profile is None:
        return HttpResponseNotFound('no such profile')


    data = dict()
    data['rid'] = profile.rid
    data['email'] = profile.user.email
    data['ci'] = profile.ci

    data['owner'] = list()
    data['member'] = list()


    for project in profile.user.project_set.all():
        ps = dict()
        ps['name'] = project.name
        ps['id'] = project.get_textid()
        data['owner'].append(ps)

    for pm in ProjectMember.objects.filter(email=profile.user.email):
        project = pm.project
        ps = dict()
        ps['name'] = project.name
        ps['id'] = project.get_textid()
        data['member'].append(ps)


    out = json.dumps(data,
        indent=4, separators=(',',': '), sort_keys=True)

    return HttpResponse(out, content_type='text/plain')


@csrf_exempt
def api_setci(request):

    remoteip = get_remoteip(request)
    ci = request.POST.get('ci',None)
    email = request.POST.get('email',None)


    log.info("API setci request email: {} ci: {} ip: {}".format(email, ci, remoteip))


    if not security_check(request):
        log.warning("security check failed, remoteip: {}".format(remoteip))
        return HttpResponse(status=401)

    if not request.POST:
        return HttpResponse(status=401)

    if ci is None or email is None:
        return HttpResponse(status=401)
    ci = int(ci)

    my_ci = myci()

    profile = Profile.objects.get(user__email=email)
    profile.set_ci(ci, force=True)
    profile.tsave()

    return HttpResponse('OK', content_type='text/plain')



def UNUSED_api_fsync(request, opts=None):
    fdict=dict() #filter dict

    remoteip = get_remoteip(request)

    if not security_check(request):
        return HttpResponse(status=401)

    log.info('accept fsync request from {}'.format(remoteip))


    for o in opts.split('/'):
        try:
            (k,v) = o.split('=',1)
            if k in fdict:
                if not isinstance(fdict[k],list):
                    fdict[k] = [fdict[k]]
                fdict[k].append(v)
            else:
                # new key
                fdict[k] = v
        except ValueError:
            pass

    te = TransactionEngine()
    backup = te.fdump(fdict)

    return HttpResponse(
        json.dumps(backup, indent=4, sort_keys=True, separators=(',',': ')),
        content_type='text/plain')


def UNUSED_api_sync(request,tstamp=None):

    remoteip = get_remoteip(request)

    if not security_check(request):
        return HttpResponse(status=401)

    log.info('accept sync request from {}'.format(remoteip))

    if tstamp is None:
        tstamp=0

    te = TransactionEngine()
    backup = te.dump(timestamp=tstamp)

    return HttpResponse(
        json.dumps(backup, indent=4, sort_keys=True, separators=(',', ': ')),
        content_type='text/plain')


def UNUSED_api_sdump(request, srid):

    if not security_check(request):
        return HttpResponse(status=401)

    te = TransactionEngine()
    backup = te.dump(srid = srid)
    return HttpResponse(
        json.dumps(backup, indent=4, sort_keys=True, separators=(',', ': ')),
        content_type='text/plain')

def api_plist(request):

    if not security_check(request):
        return HttpResponse(status=401)


    plist = []
    for p in Profile.objects.all():
        d = dict()
        d['email'] = p.user.email
        d['ci'] = p.ci
        d['rid'] = p.rid
        plist.append(d)
    return HttpResponse(
        json.dumps(plist, indent=4, sort_keys=True, separators=(',',': ')),
        content_type='text/plain')

@csrf_exempt
def api_tproc_get(request):

    def unlock_old(td=None):

        now=timezone.now()
        if not td:
            log.debug('unlock all records')
            uq = Indicator.objects.filter(lockpid__isnull=False)
        else:
            log.debug('unlock old locked records ({} ago)'.format(td))
            uq = Indicator.objects.filter(lockpid__isnull=False, lockat__lt=now-td)
        uc = uq.update(lockpid=None,lockat=None)
        log.debug("unlocked {} records".format(uc))


    def lock1(textid, iname, rnd):
        """
            lock this one indicator
            return num locked
        """
        project = Project.get_by_textid(textid)
        if project is None:
            return 0
        i = project.geti(iname)
        if i is None:
            return 0

        log.info('lock one indicator {} {}: {}'.format(textid, iname, i))

        i.lock(rnd)
        i.save()

        return 1


    def lock(pid, machine, numi=5, location='noname@nowhere.tld'):
        """
            lock numi records.
            we lock by setting lockpid to non-null (random) value.
            we cannot set to PID
            npname - netprocess name
        """


        now=timezone.now()

        remote = True

        m = re.match('([a-z]+)@([a-z]+)\.([a-z]+)', location)

        if m is None:
            log.error('Cannot parse location \'{}\''.format(location))
            return 0

        lfilter = Q(location='') | Q(location=m.group(3)) | Q(location=m.group(2)+'.'+m.group(3)) | Q(location=location)

        # hostname = 'charlie'
        # hostname = settings.HOSTNAME

        my_ci = myci()

        # nested_q=Indicator.objects.filter(lockpid__isnull=True, ci=my_ci, problem=False, disabled=False, dead=False, deleted_at__isnull=True, scheduled__lte=now, cm__remote=remote).exclude(last_fail_machine=machine).values_list('pk', flat=True)[:numi]

        if settings.HONOR_LAST_FAIL:
            nested_q = Indicator.objects.filter(lockpid__isnull=True, ci=my_ci, problem=False, disabled=False, dead=False,
                    deleted_at__isnull=True, scheduled__lte=now, cm__remote=remote)

            # location filter
            nested_q = nested_q.filter(lfilter)

            nested_q = nested_q.order_by('scheduled').exclude(Q(last_fail_machine=machine) & Q(location='')).values_list('pk', flat=True)[:numi]

        else:
            nested_q=Indicator.objects.filter(lockpid__isnull=True, ci=my_ci, problem=False, disabled=False, dead=False, deleted_at__isnull=True, scheduled__lte=now, cm__remote=remote).order_by('scheduled').values_list('pk', flat=True)[:numi]

        nlocked = Indicator.objects.filter(pk__in=list(nested_q), lockpid__isnull=True, ci=my_ci, disabled=False, deleted_at__isnull=True, scheduled__lte=now, cm__remote=remote).update(lockpid=pid,lockat=now)
        return nlocked


    ####
    # disabled
    ###

    return HttpResponse('[]',
        content_type='text/plain'
    )


    remoteip = get_remoteip(request)

    if not request.POST:
        log.info('tproc_get not POST ({}) request from {}'.format(request.method, remoteip))
        return HttpResponse("not post", status=401)

    name = request.POST.get('name', 'noname')
    location = request.POST.get('location', 'nowhere.no')
    numi = int(request.POST.get('numi', '5'))
    textid = request.POST.get('textid', None)
    iname = request.POST.get('iname', None)

    rnd = random.randint(-2147483648, 2147483647)

    redis = get_redis(settings.OKERR_REDIS_DB)
    
    if redis.exists("tproc_sleep"):
        return HttpResponse("[]", content_type='text/plain')
    
    rkey = 'okerr:remote_netprocess:{}@{}'.format(name, location)
    redis.set(rkey, remoteip)
    redis.expire(rkey, REMOTE_NETPROCESS_EXPIRATION)

    # fix numi if needed
    if numi > settings.TPROC_GET_MAX:
        numi = settings.TPROC_GET_MAX


    data = list()

    if not security_check(request):
        log.info('tproc_get fail security check for ip {}'.format(remoteip))
        return HttpResponse("security check fail", status=401)
    else:
        # log.info('tproc_get good security check for ip {}'.format(remoteip))
        pass

    # unlock_old(datetime.timedelta(0,600))
    # disabled. process will unlock old records

    if iname and textid:
        nlocked = lock1(textid, iname, rnd)
    else:
        nlocked = lock(rnd, name, numi, name + '@' + location)

    # log.info('nlocked {}'.format(nlocked))

    if nlocked > 0:
        for i in Indicator.objects.filter(lockpid=rnd):
            # print i,i.lockpid,i.lockat
            data.append(i.tproc())
        # log.info('tproc/get request from {} {}@{} {}/{}'.format(remoteip,name,location, nlocked, len(data)))
    else:
        # log.info('tproc/get request from {} {}@{} nothing'.format(remoteip,name,location))
        Indicator.update_tproc_sleep()


    return HttpResponse(
        json.dumps(data, indent=4, separators=(',',': ')),
        content_type='text/plain'
    )




@csrf_exempt
def api_tproc_set(request):
    start = time.time()
    c = 0
    # security check
    remoteip = get_remoteip(request)

    if not security_check(request):
        return HttpResponse(status=401)


    name    = str(request.POST.get('name','name-not-set'))
    res_str = request.POST.get('res')
    location = str(request.POST.get('location','location-not-set'))


    if 'simulation' in request.POST:
        log.info('simulation update')
        simulation = True
    else:
        simulation = False

    res = json.loads(res_str)


    projects = dict()

    tsr = {
        'msg': '',
        'applied': [],
        'not applied': []
        }


    for textid in res.keys():
        p = Project.get_by_textid(textid)
        if p is None:
            log.error('tproc_set not found project {}'.format(textid))
            continue

        for r in res[textid]:
            fullname = r['name']+'@'+r['textid']
            try:
                i = p.get_indicator(r['name'])
            except Indicator.DoesNotExist:
                log.error('!!! not found indicator {} in project {}'.format(r['name'], r['textid']))
                continue

            if r['code'] is None:
                log.warning('api_tproc_set None r[code] from {}@{} IP:{}'.format(name, location, remoteip))
                r['code'] = -1

            if int(r['code']) == 200:
                if r['mtime'] == dt2unixtime(i.mtime) or simulation:
                    if i.expected <= timezone.now() or simulation:
                        tsr['applied'].append(fullname)

                        log.info('apply_tproc {}@{} {} {}:"{}" {}@{} = {}'.format(
                            name, location, remoteip,
                            r['code'], r['code_message'],
                            r['name'], r['textid'], r['status']))

                        i.apply_tproc(r, name, location)
                        i.usave()
                        c+=1
                    else:
                        log.info('apply_tproc_early {}@{} {} {}:"{}" {}@{} = {}'.format(
                            name, location, remoteip,
                            r['code'], r['code_message'],
                            r['name'], r['textid'], r['status']))
                        tsr['not applied'].append(fullname)
                else:
                        log.info('apply_tproc_mtime {}@{} {} {}:"{}" {}@{} = {}'.format(
                            name, location, remoteip,
                            r['code'], r['code_message'],
                            r['name'], r['textid'], r['status']))
                        tsr['not applied'].append(fullname)
            else:
                # code not 200
                log.info('apply_tproc_fail {}@{} {} {}:"{}" {}@{} = {}'.format(
                    name, location, remoteip,
                    r['code'], r['code_message'],
                    r['name'], r['textid'], r['status']))
                i.last_fail_machine = name
                i.usave()
                tsr['not applied'].append(fullname)

    stop = time.time()
    tsr['msg'] = "{} indicators updated from {}@{} {} in {:.2f}".format(c, name, location, remoteip, stop-start)
    log.info(tsr['msg'])
    return HttpResponse(json.dumps(tsr, indent=4))


def api_listcluster(request):

    remoteip = get_remoteip(request)

    if not security_check(request):
        return HttpResponse(status=401)

    return HttpResponse(json.dumps(settings.MACHINES, indent=4, separators=(',',': '), sort_keys=True), content_type='text/plain')


def api_ip(request):
    remoteip = get_remoteip(request)
    return HttpResponse(remoteip)

def api_status(request):

    if not security_check(request):
        return HttpResponse(status=401)

    data = dict()

    if False:
        data['user']=dict()
        data['user']['uid'] = os.getuid()
        data['user']['gid'] = os.getgid()
        data['user']['groups'] = os.getgroups()

    data['lastloop'] = dict()
    data['lastloop']['lastloop'] = int(SystemVariable.get('lastloopunixtime'))
    data['lastloop']['lastloop_age'] = int(time.time() - data['lastloop']['lastloop'])

    if data['lastloop']['lastloop_age'] < 300:
        data['lastloop']['lastloop_status'] = 'OK'
    else:
        data['lastloop']['lastloop_status'] = 'ERR'

    return HttpResponse(
        json.dumps(data, indent=4, separators=(',', ': ')), content_type='text/plain')



def api_hostinfo(request):

    if not security_check(request):
        return HttpResponse(status=401)


    redis = get_redis(settings.OKERR_REDIS_DB)

    my_ci = myci()
    now=timezone.now()

    out = dict()
    out['hostname'] = settings.HOSTNAME
    out['meta_server_name'] = request.META['SERVER_NAME']
    out['meta_http_host'] = request.META['HTTP_HOST']
    out['ci'] = myci()
    out['cluster'] = settings.MACHINES
    out['TRUSTED_IPS'] = settings.TRUSTED_IPS
    out['TRUSTED_NETS'] = settings.TRUSTED_NETS
    out['remoteip'] = get_remoteip(request)
    out['myip'] = settings.MYIP
    out['uid'] = os.getuid()
    out['remote_netprocess']=list()
    out['sensors']=list()
    out['siteurl'] = settings.SITEURL

    if request.user.is_authenticated:
        out['user'] = request.user.email
    else:
        out['user'] = None

    for k in redis.keys('okerr:remote_netprocess:*'):
        rnp_name = k.split(':',3)[2] 
        rnp_ip = redis.get(k)
        rnp_age = REMOTE_NETPROCESS_EXPIRATION - redis.ttl(k)
        
        out['remote_netprocess'].append((rnp_name, rnp_ip, rnp_age))

    for k in redis.keys('okerr:sensor:hello:*'):
        sensor_name = k.split(':')[3]
        sensor_ttl = redis.ttl(k)
        sensor_uptime = redis.get(k)

        out['sensors'].append((sensor_name, sensor_uptime, sensor_ttl))

    for remote in [True, False]:
        if remote:
            suffix="remote"
        else:
            suffix="local"
        out['pending-'+suffix] = Indicator.objects.filter(lockpid__isnull=True, ci=my_ci, problem=False, disabled=False, dead=False, scheduled__lte=now, cm__remote=remote).count()
        out['locked-'+suffix] = Indicator.objects.filter(lockpid__isnull=False, ci=my_ci, problem=False, disabled=False, dead=False, scheduled__lte=now, cm__remote=remote).count()

    return HttpResponse(json.dumps(out, indent=4, separators=(',',': '), sort_keys=True), content_type='text/plain')


def api_admin_cilist(request):
    out = list()
    if not security_check(request):
        return HttpResponse(status=401)

    for p in Profile.objects.filter(ci=myci()):
        out.append(p.user.username)

    return HttpResponse('\n'.join(out)+'\n', content_type='text/plain')


def api_admin_list(request):
    out = list()
    if not security_check(request):
        return HttpResponse(status=401)

    for p in Profile.objects.all():
        out.append(dict(ci=p.ci, user=p.user.username))

    return HttpResponse(json.dumps(out, indent=4, separators=(',',': '), sort_keys=True), content_type='application/json')


def api_admin_member(request, email):
    out = list()
    if not security_check(request):
        return HttpResponse(status=401)

    # profile = Profile.objects.first(user__email = email)
    User = get_user_model()
    u = User.objects.filter(email=email).first()
    if u is None:
        # no such
        return HttpResponseNotFound('No such user')

    for p in Project.objects.filter(owner=u):
        out.append(p.get_textid())

    for pm in ProjectMember.objects.filter(email=email):
        textid = pm.project.get_textid()
        if not textid in out:
            out.append(textid)

    return HttpResponse(json.dumps(out, indent=4, separators=(',',': '), sort_keys=True), content_type='application/json')



"""
    quick summary
"""
def api_admin_qsum(request, textid):

    if not security_check(request):
        return HttpResponse(status=401)

    d = dict()

    project = Project.get_by_textid(textid)
    if not project:
        raise Http404("No such project {}".format(repr(textid)))

    d['project'] = project.name
    d['textid'] = textid
    d['cnt'] = dict()
    d['cnt']['total'] = project.indicator_set.count()
    d['cnt']['maintenance'] = project.indicator_set.filter(disabled=False, maintenance__isnull=False).count()
    d['cnt']['silent'] = project.indicator_set.filter(disabled=False, silent = True).count()
    d['cnt']['ERR'] = project.indicator_set.filter(disabled=False, maintenance__isnull=True, silent=False, _status='ERR').count()
    d['ERR'] = list()
    for i in project.indicator_set.filter(disabled=False, maintenance__isnull=True, silent=False, _status='ERR'):
        istr = dict()
        istr['name'] = i.name
        istr['status'] = i._status
        istr['details'] = i.details
        istr['changed'] = i.changed.strftime('%Y-%m-%d %H:%M:%S')
        istr['age'] = dhms(timezone.now() - i.changed)
        d['ERR'].append(istr)

    return HttpResponse(json.dumps(d, indent=4), content_type='text/plain')


def api_admin_chat_id(request, chat_id):
    profile = Profile.objects.filter(telegram_chat_id=chat_id).first()
    if profile:
        # this chat id is linked
        return HttpResponse(profile.user.email, content_type='text/plain')
    return HttpResponseNotFound('')


"""
    subscribe:
        chat_id, tgname, [email]
    unsubscribe:
        chat_id
"""

@csrf_exempt
def api_admin_tglink(request):

    if not security_check(request):
        return HttpResponse(status=401)

    tgname = request.POST.get('tgname', None)
    email = request.POST.get('email', None)
    chat_id = request.POST.get('chat_id', None)

    out = dict()
    out['sync'] = list()

    # log.info('tglink tgname: {} email: {} chat_id: {}'.format(tgname, email, chat_id))

    #try:
    #    chat_id = long(chat_id)
    #except (ValueError, TypeError):
    #    out['msg'] = 'Need chat_id'
    #    return HttpResponse(json.dumps(out, indent=4), status=400, content_type='text/plain')


    if chat_id and not tgname and not email:
        msg = ''
        # unlink by chat_id
        for p in Profile.objects.filter(telegram_chat_id = chat_id):
            p.telegram_chat_id = None
            p.save()
            msg += 'Unlinked from user {} @{}\n'.format(p.user.username, p.telegram_name)
            out['sync'].append(p.user.username)
        out['msg'] = msg
        return HttpResponse(json.dumps(out, indent=4), content_type='text/plain')

    try:
        if email:
            p = Profile.objects.get(ci = myci(), user__email = email, telegram_name = tgname)
        else:
            p = Profile.objects.get(ci = myci(), telegram_name = tgname)

    except Profile.DoesNotExist:
        msg = 'No such user {} with telegran name {} on this ci {}'.format(email, tgname, myci())

        log.debug(msg)
        out['msg'] = msg
        return HttpResponse(json.dumps(out, indent=4), content_type='text/plain')

    except Profile.MultipleObjectsReturned:
        msg = 'More then one user with telegram name {}. Use /on <email>'.format(tgname)
        log.debug(msg)
        out['msg'] = msg
        return HttpResponse(json.dumps(out, indent=4), content_type='text/plain')



    p.telegram_chat_id = chat_id
    p.save()
    out['msg'] = 'assigned to okerr user {} (@{})\n'.format(p.user.username, p.telegram_name)
    out['sync'].append(p.user.username)
    return HttpResponse(json.dumps(out), content_type='text/plain')


def api_admin_export(request,email):
    remoteip = get_remoteip(request)

    if not security_check(request):
        return HttpResponse(status=401)

    # log.info('EXPORT request for {} from {}'.format(email, remoteip))

    try:
        profile = Profile.objects.get(user__email = email)
    except Profile.DoesNotExist:
        return HttpResponseNotFound('No such profile {}'.format(email))

    ie = Impex()
    ie.set_verbosity(0)

    data = ie.export_data(profile)

    return HttpResponse(json.dumps(data, indent=4)+'\n', content_type='text/plain')

#
# api_admin_accept_invite
#
# return error as http code and reason as text
# or return user data with project after invite accepted
#

@csrf_exempt
def api_admin_accept_invite(request):
    if not security_check(request):
        return HttpResponse(status=401)

    User = get_user_model()
    email = request.POST.get('email', None)
    code = request.POST.get('code', None)
    try:
        pi = ProjectInvite.objects.get(secret = code)
    except ProjectInvite.DoesNotExist:
        return HttpResponseNotFound('No such code')

    try:
        user = User.objects.get(email = email)
    except User.DoesNotExists:
        return HttpResponseNotFound('No such user')

    project = pi.project

    status, reason = pi.local_accept(user)
    if status==False:
        return HttpResponse(reason, status=400)

    ie = Impex()
    ie.set_verbosity(0)
    data = ie.export_data(project.owner.profile)
    return HttpResponse(json.dumps(data, indent=4)+'\n', content_type='text/plain')

#
# force sync account from server
#

@csrf_exempt
def api_admin_force_sync(request):
    remoteip = get_remoteip(request)
    if not security_check(request):
        return HttpResponse(status=401)

    User = get_user_model()
    email = request.POST.get('email', None)
    server = request.POST.get('server', None)

    log.info('FORCESYNC {} {} from {}'.format(remoteip, email, server))
    # url = settings.CLUSTER_URL[server]
    rs = RemoteServer(name=server)
    data = rs.get_user(email)

    ie = Impex()
    ie.set_verbosity(0)
    ie.preimport_cleanup(data)
    ie.import_data(data)

    return HttpResponse('OK')

def api_admin_log(request, mname, start):
    remoteip = get_remoteip(request)
    if not security_check(request):
        return HttpResponse(status=401)

    limit = 20 # unused

    data = list()

    try:
        start = int(start)
    except ValueError:
        start = 0

    dt = datetime.datetime.fromtimestamp(start)

    if mname:
        qs = LogMessage.objects.filter(machine=mname, created__gte = dt)
    else:
        qs = LogMessage.objects.filter(created__gte = dt)

    # order
    qs = qs.order_by('created')

    # add limiting
    for lm in qs: # [:limit]:
        data.append(lm.export())

    return HttpResponse(json.dumps(data, indent=4), content_type='text/plain')


def api_groups(request):


    #
    # no protection. public. (really needed only for partners)
    #


    #if not security_check(request):
    #    return HttpResponse(status = 401)

    gconf = Group.get_groups()

    gconf.pop('Admin', None)  # hide admin


    for gname, gdata in gconf.items():
        if '_price' in gdata and 'maxindicators' in gdata:
            gdata['_price_1indicator'] = float(gdata['_price']) / gdata['maxindicators']

            minperiod = None
            if 'minperiod' in gdata:
                minperiod = gdata['minperiod']
            else:
                for key in gdata.keys():
                    if key.startswith('minperiod:'):
                        minperiod = int(key.split(':')[1])
                        break

            if minperiod:
                checks = round(gdata['maxindicators'] * (3600*24*30 / float(minperiod)), 6)
                gdata['_price_1check'] = round(gdata['_price']*100 / checks,5)

    return HttpResponse(json.dumps(gconf, indent=4, sort_keys=True), content_type='text/plain')


def api_test(request):
    return HttpResponse('Hello world!', content_type='text/plain')    


def get_oauth2_provider(name, request):
    """
        name: github or google or okerr:SERVERNAME
    """
    p = dict()

    myhostname = request.get_host()
    if not (('.okerr.com' in myhostname) or ('localhost' in myhostname)):
        return HttpResponse('bad hostname: {}'.format(myhostname), status=400)

    # make base url

    # base_url = request.build_absolute_uri('/')

    rs = RemoteServer.me()

    my_base_url = rs.url

    if name.startswith('okerr:') or name.endswith(".okerr.com"):

        if name.startswith('okerr:'):
            # okerr:name host specification
            codename = name.split(':')[1]
            provider = settings.OAUTH2_CLIENTS
            rs = RemoteServer(name = codename)
            auth_base_url = rs.url
        else:
            # cp.okerr.com
            provider = settings.OAUTH2_CLIENTS
            auth_base_url = 'https://{}/'.format(name)

        p['client_id'] = provider['client_id']
        p['secret'] = provider['client_secret']
        p['redirect_url'] = "{url}oauth2/callback".format(url = my_base_url)
        p['scope'] = ('read',)
        p['oauth_url'] = urljoin(auth_base_url, "/o/authorize/")
        p['token_url'] = urljoin(auth_base_url, "/o/token/")
        p['info'] = urljoin(auth_base_url, "/api/myprofile")
        p['get_email'] = lambda x: x['email']
        p['get_id'] = lambda x: x['email']
        p['autocreate'] = False
        return p


    else:
        # external providers, such as google
        #try:
        #    provider = okerr.settings_oauth.OAUTH2_PROVIDERS[name]
        #except KeyError:
        #    raise Http404("No such oauth2 provider {}".format(repr(name)))

        for p in settings.OAUTH2_LIST:
            if p['code'] == name:
                return p

    raise Http404("No such oauth2 provider {}".format(repr(name)))


def oauth2_bind(request, provider, suffix):
    request.session['oauth2_bind'] = provider
    return oauth2_login(request, provider, suffix)

def oauth2_login(request, provider, suffix):
    remoteip = get_remoteip(request)

    if request.get_host() == 'cp.okerr.com':
        rs = RemoteServer.me()
        my_base_url = rs.url
        newurl = urljoin(my_base_url, reverse('okerr:oauth2_login', kwargs = {'provider': provider, 'suffix': suffix} ) )

        log.info('oauth2_login host: {} redirect to: {}'.format(
            request.get_host(), newurl))
        return redirect(newurl)


    if suffix:
        # log.info('{} OAUTH {} login set suffix to {} skey: {}'.format(remoteip, request.get_host(), suffix, request.session.session_key))
        request.session['afterlogin_redirect'] = suffix
    else:
        log.info('no suffix in oauth2_login. redirect: {}'.format(request.session.get('afterlogin_redirect', None)))

    p = get_oauth2_provider(provider, request)


    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    # log.info("OAUTH login {} type {}".format(remoteip, provider))
    # log.info("redirect from {} (to me): {}".format(request.get_host(), p['redirect_url']))

    redirect_url = p['redirect_url'].format(SITEURL=settings.SITEURL, HOSTNAME=settings.HOSTNAME)
    redirect_url = re.sub('(?<!:)/+','/', redirect_url)

    oauth = requests_oauthlib.OAuth2Session(p['client_id'],
        redirect_uri=redirect_url,
        scope=p['scope'])

    authorization_url, state = oauth.authorization_url(
        p['oauth_url'],
        # access_type and prompt are Google specific extra
        # parameters.
        #access_type="offline", prompt="select_account")
        )


    # log.info("set provider {} for my server name {} skey: {}".format(provider, request.META['SERVER_NAME'], request.session.session_key))
    request.session['oauth2_state'] = state
    request.session['oauth2_provider'] = provider

    #for key in request.session.keys():
    #    log.info("login session[{}] = {}".format(key, request.session[key]))

    return redirect(authorization_url)



def oauth2_callback(request):

    remoteip = get_remoteip(request)

    #for key in request.session.keys():
    #    log.info("callback session[{}] = {}".format(key, request.session[key]))


    try:
        # log.info("callback try to get provider from session {} {}".format(request.session.session_key, request.META['SERVER_NAME']))
        provider = request.session['oauth2_provider']
    except KeyError:
        log.info("not found provider")
        return HttpResponse(status=400)

    if 'afterlogin_redirect' in request.session:
        afterlogin_redirect = request.session['afterlogin_redirect']
    else:
        afterlogin_redirect = None

    # log.info("OAUTH callback skey: {} provider: {} redirect: {} ".format(request.session.session_key, provider, afterlogin_redirect))

    p = get_oauth2_provider(provider, request)

    User = get_user_model()

    # log.info("OAUTH callback {} type {}".format(remoteip, provider))

    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    try:
        state = request.session['oauth2_state']
    except KeyError:
        return HttpResponse(status=400)

    # redirect_url = p['redirect_url'].format(SITEURL=settings.SITEURL)
    redirect_url = p['redirect_url'].format(SITEURL=settings.SITEURL, HOSTNAME=settings.HOSTNAME)

    redirect_url = re.sub('(?<!:)/+','/', redirect_url)
    oauth = requests_oauthlib.OAuth2Session(p['client_id'], state=state, redirect_uri=redirect_url)

    try:
        token = oauth.fetch_token(
            p['token_url'],
            client_secret=p['secret'],
            authorization_response = request.build_absolute_uri(),
#            proxies = {'https': 'http://127.0.0.1:8080'}, verify = False
            )
    except requests.exceptions.ConnectionError as e:
        return HttpResponse(str(e), status=400)
    except oauthlib.oauth2.rfc6749.errors.MissingCodeError as e:
        return HttpResponse(type(e), str(e), status=400)
    except Exception as e:
        return HttpResponse(type(e), str(e), status=400)

#    log.info('got token: {}'.format(token))

    r = oauth.get(p['info'])
    try:
        data = json.loads(r.text)
    except ValueError as e:
        return HttpResponse('Cannot parse JSON at callback from {} (http status: {}): {}'.format(
            provider, r.status_code, r.text))

    user_id = p['get_id'](data)

    if request.user.is_authenticated and request.session.get('oauth2_bind', False) == provider:
        if not Oauth2Binding.bound(request.user.profile, provider) and request.user.profile.ci == myci():
            Oauth2Binding.bind(request.user.profile, provider, user_id)
            notify(request, _("Bound profile to {}").format(provider))
        return redirect('okerr:afterlogin')
    else:
        bindings = Oauth2Binding.get_profiles(provider, user_id)

        if not bindings:
            # No binginds: Autocreate or signup
            if 'get_email' in p:
                email = p['get_email'](data)

                User = get_user_model()
                try:
                    user = User.objects.get(email=email)
                    user.backend = 'django.contrib.auth.backends.ModelBackend'

                    django_login(request, user)

                    if p.get('autocreate', True) and request.user.profile.ci == myci():
                        Oauth2Binding.bind(user.profile, provider, user_id)
                        notify(request, _("Bound profile to {}").format(provider))

                    # set afterlogin_redirect if available
                    if afterlogin_redirect:
                        request.session['afterlogin_redirect'] = afterlogin_redirect

                    return redirect('okerr:afterlogin')

                except User.DoesNotExist:
                    notify(request,
                           _('Not found user bound to this {} account. Link it in profile.').format(provider))
                    return redirect('myauth:signup')
            else:
                return redirect('myauth:signup')
        elif len(bindings) == 1:
            # 1 binding: just log in
            profile = bindings[0].profile
            profile.user.backend = 'django.contrib.auth.backends.ModelBackend'
            if not profile.can_login():
                log.error('cannot login {} from {}'.format(user.email, remoteip))
                return HttpResponse('User {} can not login (oauth)'.format(user.email))
            django_login(request, profile.user)
            # set afterlogin_redirect if available
            if afterlogin_redirect:
                request.session['afterlogin_redirect'] = afterlogin_redirect
            return redirect('okerr:afterlogin')
        else:
            # 2+ bindings: select
            request.session['oauth_provider'] = provider
            request.session['oauth_uid'] = user_id
            return redirect('okerr:oauth2_select')


def oauth2_select(request):
    provider = request.session['oauth_provider']
    user_id = request.session['oauth_uid']

    selected = request.POST.get('selected', None)

    bindings = Oauth2Binding.get_profiles(provider, user_id)

    if selected:
        for b in bindings:
            if b.profile.user.email == selected:

                profile = b.profile
                profile.user.backend = 'django.contrib.auth.backends.ModelBackend'
                if not profile.can_login():
                    log.error('cannot login {} from {}'.format(user.email, remoteip))
                    return HttpResponse('User {} can not login (oauth)'.format(user.email))
                django_login(request, profile.user)
                # set afterlogin_redirect if available
                #if afterlogin_redirect:
                #    request.session['afterlogin_redirect'] = afterlogin_redirect
                return redirect('okerr:afterlogin')

    ctx = dict(bindings=bindings, provider=provider)
    return render(request, 'okerrui/oauth2_select.html', ctx)


@login_required(login_url='myauth:login')
def api_myprofile(request):
    profile = dict()
    profile['email'] = request.user.email
    return HttpResponse(json.dumps(profile, indent=4))
