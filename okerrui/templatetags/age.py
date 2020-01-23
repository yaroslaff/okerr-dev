from django import template
import datetime
import calendar
import pytz
from django.template.defaulttags import register

import myutils


def dhms_short(sec, sep=" ", num=2):
    out=""
    nn=0
    t={'d': 86400,'h': 3600,'m': 60,'s': 1}
    for k in sorted(t,key=t.__getitem__,reverse=True):
        if sec>t[k]:
            if nn == num:
                break
            nn+=1
            n = int(sec/t[k])
            sec-=n*t[k]
            out+="%d%s%s" % (n,k,sep)
    return out.strip()

@register.simple_tag
def age(date):
    now = datetime.datetime.now(pytz.utc)
    delta = now - date
    return dhms_short(delta.total_seconds())

@register.simple_tag
def reverse_age(date):
    now = datetime.datetime.now(pytz.utc)
    delta = date - now
    return dhms_short(delta.total_seconds())


# register.filter('age', age)

