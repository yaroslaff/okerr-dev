from django.shortcuts import get_object_or_404, render, redirect
from django.http import HttpResponseRedirect, HttpResponseBadRequest, HttpResponseForbidden, HttpResponse,HttpResponseNotFound
#from django.core.urlresolvers import reverse
from django.urls import reverse

from django.views import generic
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login as django_login
from django import forms
from django.core.exceptions import ObjectDoesNotExist
from django.forms.models import modelformset_factory
from django.forms.formsets import formset_factory
from django.forms import ModelForm
from django.views.decorators.csrf import csrf_exempt
from django.db import connection, transaction
from django.conf import settings
from django.template.loader import get_template
from django.template import Context
from django.core.mail import EmailMultiAlternatives
from django.utils.translation import gettext_lazy as _, pgettext
from django.contrib.auth import get_user_model, authenticate, login, logout

from okerrui.views import security_check

import time
import urllib.parse
import datetime 
import logging

from moveauth.models import MoveAuthTicket

log = logging.getLogger('okerr')		


@csrf_exempt
def mkticket(request):
    remoteip=request.META.get('REMOTE_ADDR','???')

    if not security_check(request):
        return HttpResponse('security check failed', status=403)
    
    if not request.POST:
        return HttpResponse('get', status=403)
        
    # buid request dict
    d = dict()
    for f in ['email','time','signature']:
        d[f] = request.POST.get(f,'---')        
    
    mysig = MoveAuthTicket.request_signature(d)
    if d['signature'] != mysig:
        return HttpResponse('bad sig', status=403)

    tdiff = int(time.time()) - int(d['time'])
    if tdiff<0:
        tdiff = -tdiff
    if tdiff > 600:
        return HttpResponse('tdiff {}'.format(tdiff), status=403)
   
    User = get_user_model()
    try:
        user = User.objects.get(email=d['email'])
    except ObjectDoesNotExist:
        log.info('mkticket fail {}: no user {}'.format(remoteip, d['email']))
        return HttpResponse('no such user', status=403)
        
    ticket = MoveAuthTicket.generate(d['email'])
    
    log.info('mkticket for {}:{} {}'.format(d['email'], remoteip, ticket[:10]))
    
    return HttpResponse(ticket,status=200)
    
    
def land(request, ticket, url):
    remoteip=request.META.get('REMOTE_ADDR','???')
    target = urllib.parse.urljoin(request.scheme+"://"+request.get_host(),url)
    
    log.info("Land {} ticket: {}.. url: {}".format(remoteip, ticket[:10],url))    
    log.info("scheme: {} host: {} target: {}".format(request.scheme, request.get_host(), target))
    
    User = get_user_model()
    
    
    # verify ticket
    try:
        mat = MoveAuthTicket.objects.get(ticket=ticket)
    except ObjectDoesNotExist:
        log.warn("Land {} no such ticket {} found".format(remoteip, ticket[:10]))
        return redirect('/')

    email = mat.email
    age = timezone.now() - mat.created
    if age > datetime.timedelta(0,30):
        log.info("too old mat for {} ({})".format(email, age))
        return redirect('/')

    log.debug("authenticate user with email: "+email)



    try:
        user = User.objects.get(email=email)
    except ObjectDoesNotExist:
        log.info('land fail {}: no user {}'.format(remoteip, email))
        return redirect('/')

    log.info("Land login {} from {} ticket {}".format(email, remoteip, ticket[:10]))
    login(request, user, 'django.contrib.auth.backends.ModelBackend')
    return redirect('/'+url)
    
        
