from django.db import models
from django.conf import settings
from myutils import send_email
    
    
class LogMessage(models.Model):

    created = models.DateTimeField(auto_now_add=True, db_index = True)
    machine = models.CharField(max_length=100, default='', db_index = True)
    message = models.CharField(max_length=255, default='')
    kind = models.CharField(max_length=255, default='')

    def __unicode__(self):
        return '{time} {machine} [{kind}] {message}'.format(
            time = self.created.strftime('%Y-%m-%d %H:%M:%S'),
            machine = self.machine,
            kind = self.kind,
            message = self.message
        )
        
    def export(self):
        d = dict()
        for f in ['created', 'machine', 'message', 'kind']:
            d[f] = str(getattr(self, f)) # maybe str() would help? created is datetime
        return d

class Logger():
    machine = None
            
    def __init__(self, machine = None, mailboxes = None):
        self.machine = machine or settings.HOSTNAME
        self.mailboxes = mailboxes or settings.LOGMAIL
    
    def log(self, msg, kind=''):

        lm = LogMessage(message = msg, machine=self.machine, kind=kind)
        lm.save()

        subject = u'okerrlog {}: {}'.format(self.machine, msg)
        body = u'''
            DATETIME: {}
            MACHINE: {}
            KIND: {}
            MESSAGE: {}
            
        '''.format(
            lm.created.strftime('%Y-%m-%d %H:%M:%S'),
            self.machine,
            kind,
            msg
        )
        
        for addr in self.mailboxes:
            send_email(addr, subject=subject, what='log:'+kind, text=body)    
        
