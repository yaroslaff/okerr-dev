#!/usr/bin/env python

import os
import django
import time
import argparse
import sys
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "okerr.settings")
#from django.conf import settings

django.setup()


from myauth.models import SignupRequest
from okerrui.models import (
    LogRecord,
    Membership,
    Policy,
    ProjectInvite, 
    Project,
    IChange,
    Indicator,
    Profile,
    Throttle,
    DynDNSRecord,
    BonusActivation, 
    UpdateLog
    )

from moveauth.models import MoveAuthTicket

# from okerrui.bonuscode import BonusActivation
# from transaction.models import TransactionServer
from okerrui.impex import Impex    

lastcron = 0

cronperiod = 30


classes = [
    Membership,
    Indicator,
    ProjectInvite,
    Project,
    LogRecord,
    Policy,
    SignupRequest,
    IChange,
    BonusActivation,
    # TransactionServer,
    MoveAuthTicket,
    Impex,
    Profile,
    Throttle,
    DynDNSRecord,
    UpdateLog
]


class nocron:
    def info(self, msg):
        self.out(msg)
    def debug(self, msg):
        self.out(msg)
    def out(self,msg):
        print(msg)

def clscron(cls,log):
    mname = cls.__name__
    s = time.time()
    r = cls.cron()
    log.debug('cronmodel {} {:.2f}: {}'.format(mname, time.time() - s, r))

def cron(log=None, models=None):
    global lastcron, cronperiod

    if time.time() <= lastcron + cronperiod:
        # too early
        return

    if log is None:
        log = nocron()
        
    started = time.time()
    # log.debug("cron started {:.2f}".format(started))


    for cls in classes:

        if not models or cls.__name__ in models:
            clscron(cls, log)

    lastcron = time.time()
    log.info("cron took {:.2f}".format(lastcron - started))


    
if __name__ == '__main__':
    django.setup()        
    
    parser = argparse.ArgumentParser(description='standalone okerr cron')
    parser.add_argument('--loop',action='store_true', default=False, help='run forever in loop')
    parser.add_argument('-m', '--model', default=[], action='append', help='process only this model')
    parser.add_argument('-p', '--period', type=int, default=30, help='period (in seconds, def: 30)')

    args = parser.parse_args()  

    cronperiod = args.period

    while True:
        cron(models = args.model)
        if not args.loop:
            # not loop
            sys.exit(0)
        time.sleep(1)
        
    
    
