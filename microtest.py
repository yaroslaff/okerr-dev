#!/usr/bin/env python

import os
import sys
import datetime
import logging
import logging.handlers
import argparse


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "okerr.settings")
import django
from django.conf import settings
from okerrui.impex import Impex
from okerrui.exceptions import OkerrError

django.setup()
from okerrui.models import Profile

parser = argparse.ArgumentParser(description='okerr indicator MQ processor')

parser.add_argument('-v', '--verbose', action='store_true', default=False, help='verbose mode')
parser.add_argument('--fix', action='store_true', default=False, help='verbose mode')

args = parser.parse_args()

if args.fix:
    # any your debug/test code
    pass

if args.verbose:
    log = logging.getLogger('okerr')
    log.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.DEBUG)
    log.addHandler(handler)

print("minimal Django setup ready")
