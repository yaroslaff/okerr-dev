#!/usr/bin/env python

import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "okerr.settings")
import django
from django.conf import settings
from okerrui.impex import Impex

django.setup()
print("minimal Django setup ready")