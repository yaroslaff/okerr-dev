import calendar
import datetime

from django.template.defaulttags import register
from okerrui.models import SystemVariable

import myutils

@register.simple_tag
def getbacklog():
    return int(SystemVariable.get('process-backlog',0))

#@register.simple_tag
#def sysmaintenance():
#    if SystemVariable.get('maintenance','0') == '1':
#        return SystemVariable.get('maintenance_msg','maintenance...')
#    else:
#        return ""    

@register.simple_tag
def getlastloopage():
    now = calendar.timegm(datetime.datetime.utcnow().utctimetuple())
    llut = int(SystemVariable.get('lastloopunixtime',now))

    return now - llut
