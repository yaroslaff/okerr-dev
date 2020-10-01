# -*- coding: UTF-8 -*-

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login as django_login, logout as django_logout
from django.shortcuts import get_object_or_404, render, redirect
from django.core.mail import send_mail
from django.utils import timezone
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils.translation import ugettext as _
from django.http import HttpResponseRedirect, HttpResponseBadRequest, HttpResponseForbidden, HttpResponse, HttpResponseNotFound
from django.urls import resolve, reverse
from django.template.loader import get_template
import requests
from pprint import pprint

from django_markup.markup import formatter

from validate_email import validate_email

from okerrui.models import Profile, Throttle, Oauth2Binding, Bonus, BonusVerificationFailed, \
    BonusNotFound

# from okerrui.bonuscode import BonusCode
from okerrui.views import notify
from okerrui.cluster import RemoteServer

import random
import string
import re
import datetime
import logging

# Create your views here.

import myutils
from myutils import get_remoteip

from myauth.models import SignupRequest

import logmessage.models 

mainpage = 'okerr:index'
afterlogin = 'okerr:afterlogin'
afterlifepage = 'okerr:afterlife'

#log=myutils.openlog()
log = logging.getLogger('okerr')
logger = logmessage.models.Logger()



def create_user(request, email, password=None, send_email=True):

    context = {}
    loginurl=request.build_absolute_uri(reverse('myauth:login'))
    remoteip = get_remoteip(request)

    if password is None:
        # generate password
        password = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(10))
    
    
    # create user           
    user = User.objects.create_user(email, email, password)
                
    # create profile for him
    profile = Profile(user=user)

    profile.save()
    profile.inits()
    
    # add to group User 
    profile.assign(group=settings.START_GROUP, time=None)
                    
    context['username'] = email
    context['password'] = password
    context['user'] = user


    if send_email:
        subj = 'Okerr registration information'

        plaintext = get_template('afterreg.txt')
        htmly = get_template('afterreg.html')

        mail_ctx = {
            'username': email,
            'password': password,
            'loginurl': loginurl,
            'hostname': settings.HOSTNAME,
            'MYMAIL_FOOTER': settings.MYMAIL_FOOTER,
            }

        text_content = plaintext.render(mail_ctx)
        html_content = htmly.render(mail_ctx)

        myutils.send_email(email, subject=subj, text=text_content, html=html_content, what='signup')
    
    logger.log('registered user: {} from ip: {}'.format(user.username, remoteip), kind='reg')

    return context


#
# verify code and create user
#
def verify(request):
    myfrom=settings.FROM
    loginurl=request.build_absolute_uri(reverse('myauth:login'))

    remoteip = get_remoteip(request)

    context = {}
    if request.GET.get('email', None) and request.GET.get('code', None):
        email = request.GET['email']
        code = request.GET['code']
        
        if SignupRequest.objects.filter(email=email,code=code).count()==1:
            # good! create user, delete request
            SignupRequest.objects.filter(email=email,code=code).delete()

            # generate password
            password = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(10))


            # maybe already has such user?
            utry = User.objects.filter(username=email).first()
            
            if utry:
                utry.set_password(password)
                utry.save()
                context['error_message']='We have sent you email with new password'
                log.info("Recovered password for user '{}'".format(email))

                subj = 'Okerr new password'
      
                plaintext = get_template('newpassword.txt')
                htmly = get_template('newpassword.html')
        
                ctx = { 
                    'username': email, 
                    'password': password, 
                    'loginurl': loginurl,
                    'hostname': settings.HOSTNAME,
                    'MYMAIL_FOOTER': settings.MYMAIL_FOOTER                    
                    }

                text_content = plaintext.render(ctx)
                html_content = htmly.render(ctx)        
                       
                myutils.send_email(email, subject=subj, text=text_content, html=html_content, what='signup')
                    
                return render(request, 'myauth/empty.html',context)
                

            # create user           
            context = create_user(request, email)                       
                
            #if user:
            log.info("created user {}".format(context['username']))               
            return render(request, 'myauth/registered.html', context)
            #else:
            #    context['error_message']="failed to create user %s" % user.name
            #    log.warning("fail to create user '{}'".format(email))

        else:
            context['error_message']='Sorry, bad verification code'
            log.warning("bad reg verification code email '{}' code '{}'".format(email,code))
           
    return render(request, 'myauth/verify.html',context)

@login_required(login_url='/login')
def profile(request):

    sudoers = getattr(settings, 'SUDOERS', list())

    msg = []
    context = {'msg': msg}
    profile = request.user.profile
    context['profile'] = profile
    context['groups'] = profile.groupstext()
    context['perks'] = profile.perkstext()
    context['args'] = profile.groupargs()
    context['qi'] = profile.get_qindicators()    
    context['oauth2_bound'] = list()
    context['oauth2_notbound'] = list()

    if hasattr(settings, 'OAUTH2_ADV_LIST'):
        for p in settings.OAUTH2_ADV_LIST:
            if Oauth2Binding.bound(profile, p['code']):
                context['oauth2_bound'].append(p)
            else:
                context['oauth2_notbound'].append(p)

    remoteip=get_remoteip(request)

    sync = False

    textnamere=re.compile('^[a-z0-9\.\-\_]+$')
 
    if 'danger' in request.session:
        msg.append('danger is set')
    
    if request.COOKIES.get('noredirect', ''):
        msg.append('noredirect is set')

    if request.POST.get('oauth_clean', None):
        Oauth2Binding.rmprofile(profile)

    if request.POST.get('change', False):
        # context['error_message']='submitted'
        request.user.first_name=request.POST.get('first_name', '')
        request.user.last_name=request.POST.get('last_name', '')

        # bonuscode
        if len(request.POST.get('bonus_code', '')) > 0:
            bonuscodename = request.POST['bonus_code']

            if hasattr(settings, 'SPECIAL_CODES'):
                if bonuscodename in settings.SPECIAL_CODES:
                    request.session['bonuscode:' + bonuscodename] = True
                    notify(request, 'Enabled bonus code {}'.format(bonuscodename))
                    return redirect('myauth:profile')

            if hasattr(settings, 'DANGER_CODE') and bonuscodename == settings.DANGER_CODE:
                log.info("set DANGER for user {}".format(request.user.username))
                notify(request, 'set DANGER for {}'.format(request.user))
                request.session['danger'] = True
                # return render(request,'myauth/profile.html',context)
                return redirect('myauth:profile')
                # return HttpResponseRedirect("")

            if bonuscodename.startswith('sudo:') and request.user.email in sudoers:
                sudo, username = bonuscodename.split(':', 1)
                user = Profile.find_user(username)
                if user:
                    olduser = request.user
                    user.backend = 'django.contrib.auth.backends.ModelBackend'
                    log.info('SUDO {} sudo to {}'.format(request.user, user))                
                    django_login(request, user)
                    request.session['presudo']=olduser.email
                    return redirect(request.path)

            if bonuscodename == 'noredirect':
                resp = redirect('myauth:profile')
                log.info("set noredirect for user {} (host: {})".format(request.user.username, request.META['HTTP_HOST']))
                if 'localhost' in request.META['HTTP_HOST']:
                    resp.set_cookie('noredirect', '1')
                elif 'okerr.com' in request.META['HTTP_HOST']:                
                    resp.set_cookie('noredirect', '1', domain='.okerr.com')
                else:
                    log.error('Dont know how to set noredirect for host: {}'.format(request.META['HTTP_HOST']))
                # return HttpResponseRedirect("")
                # return render(request,'myauth/profile.html',context)
                # return HttpResponseRedirect("")
                return resp
                
            if bonuscodename == 'redirect':
                # return render(request,'myauth/profile.html',context)
                resp = redirect('myauth:profile')
                if 'localhost' in request.META['HTTP_HOST']:
                    resp.delete_cookie('noredirect')
                elif 'okerr.com' in request.META['HTTP_HOST']:                
                    resp.delete_cookie('noredirect', domain='.okerr.com')
                else:
                    log.error('Dont know how to delete redirect for host: {}'.format(request.META['HTTP_HOST']))

                return resp

            try:
                b = Bonus.get_by_code(bonuscodename, internal=False)
            except BonusNotFound as e:
                notify(request, _("No bonus code '{}'").format(bonuscodename))
                return redirect(request.path)

            try:
                b.apply(profile, bonuscodename)
            except BonusVerificationFailed as e:
                notify(request, _("Not applied: {}").format(e))
                return redirect(request.path)

            notify(request, _('Applied bonus code "{}"'.format(bonuscodename)))
            return redirect(request.path)
            
        # password change
        if len(request.POST.get('pass1', ''))>0:
            if request.POST['pass1'] == request.POST.get('pass2',''):
                if authenticate(username=request.user.username, password=request.POST.get('password','')):
                    # change pass
                    request.user.set_password(request.POST['pass1'])
                    request.user.save()
                    context['error_message'] = _('password changed')
                else:
                    context['error_message'] = _('must provide valid current password')
            else:
                context['error_message'] = _('passwords does not match')

            logger.log(u'pass change user {} from ip: {} status: {}'.format(
                request.user.username, remoteip, context['error_message']), 
                kind='profile')


        # send alerts, summaries
        if 'sendsummary' in request.POST:
            profile.sendsummary = True
        else:
            profile.sendsummary = False
            
        if 'sendalert' in request.POST:
            profile.sendalert = True   
        else:
            profile.sendalert = False

        if 'sumtime' in request.POST:
            try:
                hh,mm=request.POST['sumtime'].split(':')
                hh=int(hh)
                mm=int(mm)
                if hh>=0 and hh<=23 and mm>=0 and mm<=59:
                    # good config
                    profile.sumtime=hh*3600+mm*60
                    # reschedule
                    profile.nextsummary = \
                    timezone.now().replace(hour=hh,minute=mm, second=0,
                    microsecond=0)
                    profile.schedulenext()
                    log.info('user {user} changed sumtime to {hh}:{mm}'\
                    ' ({sumtime}), next summary: {nextsummary}'.format(
                        user=request.user.username, hh=hh, mm=mm,
                        sumtime=profile.sumtime,
                        nextsummary=profile.nextsummary))
                else:
                    raise ValueError
            except ValueError:
                notify(request, 'Send alerts time must be in HH:MM format, e.g. 6:30')

        if request.POST.get('suicide', False):
            # check confirmation phrase
            iamsure=request.POST.get('iamsure', '')
            if iamsure == u'Да, я уверен!' or iamsure == 'Yes, I am sure!':
                # delete user
                log.info('suicide u: {} ip: {}'.\
                    format(request.user.username, remoteip))
                # profile.set_delete()
                # profile.touch()
                # profile.save()

                user = request.user
                logger.log('user: {} suicided ip: {}'.format(request.user.username, remoteip), kind='reg')
                django_logout(request)
                profile.predelete()  # deletes user too
                profile.delete()
                return redirect(afterlifepage)
            else:
                notify(request, 'bad delete confirmation phrase')

        if request.POST.get('telegram_name', '') != profile.telegram_name:
            profile.telegram_name = request.POST.get('telegram_name')
            profile.telegram_chat_id = None
            if profile.telegram_name:
                notify(request, _('Configured telegram username. Now send /on command to telegram bot @OkerrBot'))
            else:
                notify(request, _('Cleared telegram username. No messages will be send.'))
            sync = True

        request.user.save()
        profile.save()
        
        if sync:
            profile.force_sync()        
                
        return redirect(request.path)       

    return render(request, 'myauth/profile.html', context)



def signup(request):
    vlink = request.build_absolute_uri(reverse('myauth:verify'))

    remoteip=get_remoteip(request)
        
    User = get_user_model()
    msg = []
    context = {'msg': msg}
    if request.POST.get('email', None):
        email = request.POST.get('email')

        # fake registration part

        fake_domain = getattr(settings, 'FAKE_DOMAIN', None)
        if fake_domain and email.endswith(fake_domain):
            if User.objects.filter(username=email).first():
                notify(request, _('Already has registered user {}').format(email))
                return redirect(request.path)
            user = create_user(request, email=email,
                               password=getattr(settings, 'FAKE_DOMAIN_PASS', email[:-len(fake_domain)]),
                               send_email=False)['user']
            user.profile.sendalert = False
            user.profile.sendsummary = False
            user.profile.save()
            log.info("created user {}".format(email))
            user.backend = 'django.contrib.auth.backends.ModelBackend'
            django_login(request, user)
            request.session['firstlogin'] = True
            return redirect(afterlogin)

        if not request.POST.get('iaccept', False):
            msg.append(_('You have to accept EULA to start using okerr'))
        elif validate_email(email):

            # quick registration if verified by oauth2
            if 'oauth2_email' in request.session and request.session['oauth2_email'] == email:
                context = create_user(request, email)  
                log.info("created user {}".format(context['username']))
                context['user'].backend = 'django.contrib.auth.backends.ModelBackend'                                               
                django_login(request, context['user'])
                request.session['firstlogin'] = True
                return redirect(afterlogin)

            # check, maybe already recently signed up
            if SignupRequest.objects.filter(email=email).count() > 0:
                msg.append(_('Already has signup from {}').format(email))
            elif User.objects.filter(username=email).first():
                msg.append(_('Already has registered user {}').format(email)) 
            else:

                sr = SignupRequest()
                sr.email = email
                sr.gencode()
                sr.save()
    
                plaintext = get_template('regcode.txt')
                htmly     = get_template('regcode.html')
        
                # send email with code
                subj='Okerr registration code'
                ctx = { 
                    'code': sr.code, 
                    'vlink': vlink, 
                    'email': email,
                    'hostname': settings.HOSTNAME,
                    'MYMAIL_FOOTER': settings.MYMAIL_FOOTER                    
                }

                text_content = plaintext.render(ctx)
                html_content = htmly.render(ctx)        
                       
                myutils.send_email(email, subject=subj, text=text_content, html=html_content, what='signup')

                logger.log('signup email {} from ip: {}'.format(email, remoteip), kind='reg')
                     
                context['email'] = email
                return render(request, 'myauth/aftersignup.html', context)
        else:
            context['error_message'] = 'bad email'
            
    try:
        context['email'] = request.session['oauth2_email']
    except KeyError:
        context['email'] = ''

    if request.LANGUAGE_CODE in ['ru', 'en']:
        context['lang_code'] = request.LANGUAGE_CODE
    else:
        context['lang_code'] = 'en' #default


    return render(request,'myauth/signup.html',context)

def logout(request):

    if 'presudo' in request.session:      
        user = Profile.find_user(request.session['presudo'])
        if user:
            # del request.session['presudo']
            user.backend = 'django.contrib.auth.backends.ModelBackend'
            log.info('BackSUDO {} sudo to {}'.format(request.user, user))                
            django_login(request, user)
            return redirect('myauth:profile')

    django_logout(request) 
    return redirect('myauth:login')

def recover(request):
    context={}
    vlink=request.build_absolute_uri(reverse('myauth:verify'))
    
    email = request.POST.get('email', None)

    if not email:
        email = request.POST.get('email', None)
        return render(request, 'myauth/recover.html', context)

    thkey = 'myauth:recover:'+email
    
    if not validate_email(email):
        context['error_message']='bad email syntax'
        return render(request,'myauth/recover.html',context)    

    try:
        th = Throttle.get(thkey)
    except Throttle.DoesNotExist:
        # good, not throttled
        pass
    else:
        notify(request, _('Already had such request for user {} recently. Try again later').format(email))
        return redirect(request.path)
    
    # do not send if no such user!
    # maybe already has such user?
    utry = User.objects.filter(username=email).first()

    if not utry:
        print("attempt to recover for non-existent user",email)
        context['email']=email
        return render(request,'myauth/afterrecover.html',context)                               

    sr = SignupRequest()
    sr.email=email
    sr.gencode()
    sr.save()

    # send email with code
    subj='Okerr password recovery'

    plaintext = get_template('password-recovery.txt')
    htmly     = get_template('password-recovery.html')

    # send email with code
    subj='Okerr password recovery'
    
    
    ctx = { 
        'code': sr.code, 
        'vlink': vlink, 
        'email': email,
        'hostname': settings.HOSTNAME,
        'MYMAIL_FOOTER': settings.MYMAIL_FOOTER                    
        }
        
    text_content = plaintext.render(ctx)
    html_content = htmly.render(ctx)        
           
    myutils.send_email(email, subject=subj, text=text_content, html=html_content, what='signup')

    Throttle.add(thkey, priv=None, expires=datetime.timedelta(hours=1))
       
    context['email']=email
    return render(request,'myauth/afterrecover.html',context)               

def login(request):
    context={}

    remoteaddr=get_remoteip(request)

    if request.session.session_key is None:
        request.session.create()
        # log.info('{} LOGIN {} no session key, created: {}'.format(remoteaddr, request.get_host(), request.session.session_key))
        

    # this should be before redirect to afterlogin
    if request.GET.get('next', None):                           
        # log.info('{} LOGIN {} set afterlogin_redirect = {}'.format(remoteaddr, request.get_host(), request.GET.get('next'))) 
        request.session['afterlogin_redirect'] = request.GET.get('next')

    if request.user.is_authenticated:
        return redirect(afterlogin)

    # log.info("LOGIN. afterlogin_redirect: {}".format(request.session.get('afterlogin_redirect',None)))

    # redirect to hostname page
    if request.get_host() == 'cp.okerr.com':            
        rs = RemoteServer(name = settings.HOSTNAME)
        url = rs.reverse('myauth:login')
    
        if request.GET.get('next',None):
            url += '?next='+request.GET['next']
        log.info('{} LOGIN redirect to {}'.format(remoteaddr, url))
        return redirect(url)

    context['next'] = request.GET.get('next', '')

    context['providers'] = dict()
#    for provider, pstruct in okerr.settings_oauth.OAUTH2_ADV_PROVIDERS.items():
#        if pstruct['enabled'] and pstruct.get('display', True):
#            pd = dict()
#            pd['title'] = pstruct['title']
#            pd['logo'] = pstruct['logo']
#            context['providers'][provider] = pd

    context['oauth2_providers'] = list()
    for provider in settings.OAUTH2_ADV_LIST:
        pd = dict()
        pd['code'] = provider['code']
        pd['title'] = provider['title']
        pd['logo'] = provider['logo']
        context['oauth2_providers'].append(pd)

    if request.POST.get('username', False) and request.POST.get('password', False):

        if not validate_email(request.POST['username']):
            # context['error_message'] = "Bad email address"
            notify(request, _('Bad email address'))
            return render(request, 'myauth/login.html', context)

        username = request.POST['username']
           
        user = authenticate(username=username, password=request.POST['password'])
        if user is not None:
                    
            if user.is_active and user.profile.deleted_at is None:
                log.info("login {} {}".format(remoteaddr,username))
                profile = user.profile
                # profile.lastlogin = timezone.now()
                profile.save()
             
                if 'afterlogin_redirect' in request.session:
                    afterlogin_redirect = request.session['afterlogin_redirect']
                else:
                    afterlogin_redirect = None

                if not profile.can_login():        
                    log.error('cannot login {} {} (web login)'.format(user.email, remoteaddr))
                    return HttpResponse(_('User {} can not login (web login)').format(user.email))

                django_login(request, user)

                if afterlogin_redirect:
                    request.session['afterlogin_redirect'] = afterlogin_redirect
             
                return redirect(afterlogin)
            else:
                log.info("no login, acount disabled {}".format(username))
                notify(request, _("Account disabled"))
        else:

            log.info("failed login {} {}".format(remoteaddr,username))
            notify(request, _("Wrong login/password"))

    context['prelogin'] = None

    if getattr(settings, 'PRELOGIN_MESSAGE_URL', None):
        try:
            r = requests.get(settings.PRELOGIN_MESSAGE_URL, timeout=2)
            if r.status_code == 200:
                context['prelogin'] = r.text
        except requests.RequestException as e:
            pass

    return render(request, 'myauth/login.html', context)

def demologin(request):
    demouser = "okerrdemo@maildrop.cc"
    demopass = "okerrdemo"

    remoteaddr=get_remoteip(request)
       
    user = authenticate(username=demouser, password=demopass)
    if user is not None:
                
        if user.is_active and user.profile.deleted_at is None:
            log.info("demo login {} {}".format(remoteaddr,demouser))
            profile = user.profile
            # profile.lastlogin = timezone.now()
            profile.save()
            django_login(request, user)
            return redirect(mainpage)
        else:
            log.info("no login, acount disabled {}".format(demouser))
            context['error_message'] = "Account disabled"

def error(request):
    return HttpResponseForbidden("Error: "+str(request.user))
