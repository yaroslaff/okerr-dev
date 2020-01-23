"""
WSGI config for okerr project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/1.6/howto/deployment/wsgi/
"""

import os
import sys
BASE_DIR = os.path.dirname((os.path.dirname(os.path.realpath(__file__))))

#sys.path.append(os.path.join(BASE_DIR,'lib/python2.7/site-packages'))

sys.path.append('/opt/venv/okerr/lib/python3.5/site-packages/')
sys.path.append(os.path.join(BASE_DIR,'okerr'))
sys.path.append(os.path.join(BASE_DIR,'okerr','okerr'))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
