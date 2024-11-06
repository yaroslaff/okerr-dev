"""
Django settings for okerr project.

For more information on this file, see
https://docs.djangoproject.com/en/1.6/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.6/ref/settings/
"""

import logging
from logging.handlers import SysLogHandler
import datetime
import json
#import imp
import importlib.machinery
import socket
import random
import string

import myutils
from django.utils.translation import gettext_lazy as _

#log = logging.getLogger('okerr')

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os
import sys
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

MAIN_CONF_DIR='/etc/okerr'
SITE_PRECONF_FILES = sorted(os.path.join(MAIN_CONF_DIR, BASENAME) for BASENAME in ['okerr.conf'] )
SITE_CONF_DIRS = sorted(os.path.join(MAIN_CONF_DIR, o) for o in os.listdir(MAIN_CONF_DIR)
                  if o.endswith('.d') and os.path.isdir(os.path.join(MAIN_CONF_DIR, o)))
SITE_POSTCONF_FILES = sorted(os.path.join(MAIN_CONF_DIR, BASENAME) for BASENAME in ['post.conf'] )

SITE_JSON_DIRS = ['/etc/okerr/json/']

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# take from environment

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.6/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!

#with open('/etc/okerr/secret_key.txt') as f:
#     SECRET_KEY = f.read().strip()

#SECRET_KEY = ''.join([random.SystemRandom().choice("{}{}{}".format(string.ascii_letters, string.digits, string.punctuation)) for i in range(50)])




# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

IMPORT_VERBOSITY = 0

def import_config_file(path):

    # site-specific overrides
    try:
        # local = imp.load_source('okerr.local', path)
        loader = importlib.machinery.SourceFileLoader(path, path)
        m = loader.load_module()
        load = True

        verbosity = IMPORT_VERBOSITY


        # check if we should load this file
        for sym in dir(m):
            if sym.startswith('__IF_'):
                symval = m.__dict__[sym]
                localsym = sym[5:]
                localsymval = globals()[localsym]

                if localsymval != symval:
                    load = False
                    break

        if load:
            if verbosity >= 1:
                print("Load {}".format(path))

            for sym in dir(m):
                # skip modules, functions etc.
                if type(m.__dict__[sym]) not in [str, list, dict, datetime.timedelta, tuple, bool, int, type(None)]:
                    continue

                # skip python special module attributes like __file__, __name__
                if sym.startswith('__'):
                    continue

                symval = m.__dict__[sym]
                globals()[sym] = symval
                if verbosity == 2:
                    print("    {}".format(sym))
                if verbosity >= 3:
                    print("    {} = {}".format(sym, repr(symval)))
        else:
            if verbosity >= 1:
                print("Skip loading {} ( {} = {!r} != {!r})".format(path, sym, symval, localsymval))
            pass

    except IOError as e:
        pass

# import defaults
import_config_file(os.path.join(os.path.dirname(__file__), 'settings_default.py'))

#DEBUG_TOOLBAR_PANELS = (
#  'debug_toolbar.panels.versions.VersionsPanel',
#  'debug_toolbar.panels.timer.TimerPanel',
#  'debug_toolbar.panels.profiling.ProfilingPanel',
#)


DEBUG_TOOLBAR_PANELS = [
    'debug_toolbar.panels.versions.VersionsPanel',
    'debug_toolbar.panels.timer.TimerPanel',
   # 'debug_toolbar.panels.settings.SettingsPanel',
   # 'debug_toolbar.panels.headers.HeadersPanel',
   # 'debug_toolbar.panels.request.RequestPanel',
    'debug_toolbar.panels.sql.SQLPanel',
   # 'debug_toolbar.panels.staticfiles.StaticFilesPanel',
    'debug_toolbar.panels.templates.TemplatesPanel',
   # 'debug_toolbar.panels.cache.CachePanel',
   # 'debug_toolbar.panels.signals.SignalsPanel',
   # 'debug_toolbar.panels.logging.LoggingPanel',
   # 'debug_toolbar.panels.redirects.RedirectsPanel',
    'debug_toolbar.panels.profiling.ProfilingPanel',
   ]




ALLOWED_HOSTS = ['localhost','127.0.0.1']

#print "ALLOWED_HOSTS: {}".format(ALLOWED_HOSTS)


# Application definition

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # 'debug_toolbar',
#    'test_without_migrations',
#    'social_django',
#    'maintenancemode',
    'oauth2_provider',
#    'corsheaders',
    'django_markup',
    'okerrui.apps.okerruiApp',
    'myauth',
    'logmessage',
    'transaction',
    'moveauth'
)


MIDDLEWARE = (
#    'johnny.middleware.LocalStoreClearMiddleware',
#    'johnny.middleware.QueryCacheMiddleware',
    # 'debug_toolbar.middleware.DebugToolbarMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
#    'maintenancemode.middleware.MaintenanceModeMiddleware',
    'okerrui.middleware.LSlashMiddleware',
#    'corsheaders.middleware.CorsMiddleware',
#    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'oauth2_provider.middleware.OAuth2TokenMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
#    'ipcontrol.IPControlMiddleware',
#    'eula.EULAMiddleware',
)

#CORS_ORIGIN_ALLOW_ALL = True

ROOT_URLCONF = 'okerr.urls'

WSGI_APPLICATION = 'okerr.wsgi.application'


# Internationalization
# https://docs.djangoproject.com/en/1.6/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.6/howto/static-files/

STATIC_URL = 'https://static.okerr.com/'
# STATIC_URL = '/static/'
STATIC_ROOT = '/var/www/virtual/static.okerr.com/'


# TEMPLATE_DIRS = [os.path.join(BASE_DIR, 'templates')]

#TEMPLATE_CONTEXT_PROCESSORS=('django.core.context_processors.i18n',
#'django.contrib.auth.context_processors.auth','django.core.context_processors.request')

# TEMPLATE_CONTEXT_PROCESSORS=('django.template.context_processors.i18n',
# 'django.contrib.auth.context_processors.auth','django.template.context_processors.request')

TEMPLATE_DEBUG=False

TEMPLATES = [
    {
#        'TEMPLATE_DEBUG': False,
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [ os.path.join(BASE_DIR, 'templates') ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'okerrui.context_processors.my_settings',
#                'social_django.context_processors.backends',
#                'social_django.context_processors.login_redirect',

            ],
        },
    },
]



LOGIN_URL = "/login"

# SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL = True
# SOCIAL_AUTH_LOGIN_REDIRECT_URL = "okerr:afterlogin"
# SOCIAL_AUTH_LOGIN_URL = "/auth/login/"
# SOCIAL_AUTH_LOGIN_ERROR_URL = "/auth/error"
# SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = '346226433207-fcjtfans16b58pf4vnk1gr3lf6fnosrl.apps.googleusercontent.com'
# SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET ='UNlMtOBoL5dDDX7lAJUWIYhP'

# SOCIAL_AUTH_PIPELINE = (
#        'social_core.pipeline.social_auth.social_details',
#        'social_core.pipeline.social_auth.social_uid',
#        'social_core.pipeline.social_auth.auth_allowed',
#        'social_core.pipeline.social_auth.social_user',
#        'social_core.pipeline.social_auth.associate_by_email',
#        'social_core.pipeline.user.get_username',
#        'social.pipeline.user.create_user',
#        'social_core.pipeline.social_auth.associate_user',
#        'social_core.pipeline.social_auth.load_extra_data',
#        'social_core.pipeline.user.user_details',
#)

AUTHENTICATION_BACKENDS = (
    # social
#    'social_core.backends.open_id.OpenIdAuth',
#    'social_core.backends.google.GoogleOpenId',
#    'social_core.backends.google.GoogleOAuth2',
#    'social_core.backends.google.GoogleOAuth',
#    'social_core.backends.twitter.TwitterOAuth',
#    'social_core.backends.yahoo.YahooOpenId',

    # oauth2
    'oauth2_provider.backends.OAuth2Backend',


    # for login/pass
    'django.contrib.auth.backends.ModelBackend',
)


LOCALE_PATHS = (
    os.path.join(BASE_DIR, 'locale'),
#    os.path.join(BASE_DIR,'okerrui/locale'),
#    os.path.join(BASE_DIR,'templates/okerrui/locale')
    )

STATICFILES_DIRS = (
#    os.path.join(BASE_DIR, "static"),
)


LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(module)s %(message)s'
        },
        'simple': {
            'format': '{message}',
            'style': '{',
        }
    },
    'filters': {
		'require_debug_false': {
		    '()': 'django.utils.log.RequireDebugFalse'
	    }
    },
    'handlers': {
        'mail_admins': {
			'level': 'ERROR',
			#'filters': ['require_debug_false'],
			'class': 'django.utils.log.AdminEmailHandler'
		},
#		'syslog': {
#			'level': 'DEBUG',
#			'class': 'logging.handlers.SysLogHandler',
#			'formatter': 'verbose',
#			'facility': SysLogHandler.LOG_LOCAL1,
#			'address': '/dev/log'
#		}
#        'okerrlog': {
#            'level': 'DEBUG',
#            'class': 'logging.FileHandler',
#            'filename': '/var/log/okerr.log',
#        }

    },
	'loggers': {
        'django': {
            'handlers': ['mail_admins',],
            'propagate': True,
            'level': 'DEBUG',
        },
		'django.request': {
			'handlers': ['mail_admins'],
			'level': 'ERROR',
			'propagate': True,
        },
		'okerr': {
			'handlers': [],
            'level': 'INFO',
			'propagate': False,
		}
    }
}


if LOG_SYSLOG:
    LOGGING['handlers']['syslog'] =  {
			'level': 'DEBUG',
			'class': 'logging.handlers.SysLogHandler',
			'formatter': 'verbose',
			'facility': SysLogHandler.LOG_LOCAL1,
			'address': '/dev/log'
		}
    LOGGING['loggers']['okerr']['handlers'].append('syslog')



if LOG_STDOUT:
    LOGGING['handlers']['console'] =  {
			'level': 'DEBUG',
			'class': 'logging.StreamHandler',
			'formatter': 'simple',
		}
    LOGGING['loggers']['okerr']['handlers'].append('console')

if LOG_SERVER:
    LOGGING['handlers']['logserver'] = {
			'level': 'DEBUG',
			'class': 'logging.handlers.SysLogHandler',
			'formatter': 'verbose',
			'facility': SysLogHandler.LOG_LOCAL1,
			'address': (LOG_SERVER, 514)
    }
    LOGGING['loggers']['okerr']['handlers'].append('logserver')


# Database
# https://docs.djangoproject.com/en/1.6/ref/settings/#databases

DATABASES = {
    'default': {
        'NAME': 'okerr',
        'ENGINE': 'django.db.backends.mysql',
        'USER': 'okerr',
        'PASSWORD': 'okerrpass',
        'HOST': DB_HOST,
        'CONN_MAX_AGE': 1800,
        'OPTIONS': {
            'sql_mode': 'STRICT_ALL_TABLES'
        },

        'TEST': {
            'NAME': 'okerr_test'
        }
    }
}

# Only this two languages are supported now
LANGUAGES = [
  ('ru', _('Russian')),
  ('en', _('English')),
]


#
# IMPORT CONFIG FILES
#


old_dwb = sys.dont_write_bytecode
sys.dont_write_bytecode = False

for conffile in SITE_PRECONF_FILES:
    if os.path.isfile(conffile):
        import_config_file(conffile)

for confdir in SITE_CONF_DIRS:
    if not os.path.isdir(confdir):
        continue

    for filename in sorted(os.listdir(confdir)):
        if not (filename.endswith('.conf')):
            continue

        path = os.path.join(confdir, filename)
        import_config_file(path)

for conffile in SITE_POSTCONF_FILES:
    if os.path.isfile(conffile):
        import_config_file(conffile)


sys.dont_write_bytecode = old_dwb


for jsondir in SITE_JSON_DIRS:
    filename = os.path.join(jsondir, 'keys-template.json')
    if os.path.exists(filename):
        with open(filename) as f:
            JKEYS_TPL = f.read().strip()

# convert imported variables

if isinstance(TRUSTED_NETS, str):
    TRUSTED_NETS = [ net for net in TRUSTED_NETS.split(' ') if net ]

if isinstance(TRUSTED_IPS, str):
    TRUSTED_IPS = [ ip for ip in TRUSTED_IPS.split(' ') if ip ]

if isinstance(TRUSTED_HOSTS, list):
    thlist = TRUSTED_HOSTS
else:    
    # list comprehension because we allow more then one space as separator, e.g. "alpha  bravo"
    thlist = [ h for h in TRUSTED_HOSTS.split(' ') if h ]

for th in thlist:

    ip = None

    try:
        ip = socket.inet_aton(th)
        ip = th
    except socket.error:
        try:
            ip = socket.gethostbyname(th)
        except socket.gaierror:
            pass    

    if ip and not ip in TRUSTED_IPS:
        TRUSTED_IPS.append(ip)

DEBUG = bool(DEBUG)
LOG_SYSLOG = bool(LOG_SYSLOG)
LOG_STDOUT = bool(LOG_STDOUT)
HONOR_LAST_FAIL = bool(HONOR_LAST_FAIL)

SITEURL = SITEURL or "https://{}/".format(HOSTNAME)
                
if not SITEURL.endswith("/"):
    SITEURL+="/"

# end of convert...

assert(len(HOSTNAME) > 3)

# Basic sanity check: hostname must be in cluster
assert(any( MACHINES[mi]['name'] == HOSTNAME for mi in MACHINES.keys() ))
