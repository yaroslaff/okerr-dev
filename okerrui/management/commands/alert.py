#!/usr/bin/env python
from django.core.management.base import BaseCommand, CommandError
from okerrui.models import AlertRecord
from django.contrib.auth import get_user_model
from django.utils import timezone
from myutils import dhms

class Command(BaseCommand):
    help = 'Manage alert records'
    
    def __init__(self):
        super(Command,self).__init__()

    def add_arguments(self,parser):                

        parser.add_argument('--user', metavar='EMAIL', default=None, help='User by email')
        parser.add_argument('--id', default=None, help='indicator ID')
        parser.add_argument('--delete', default=False, action='store_true', help='indicator ID')
        parser.add_argument('--proto', '-p', default=None, help='protocol (mail, telegram)')


    def handle(self, *args, **options):
        User = get_user_model()

        qs = AlertRecord.objects

        if options['user']:
            user = User.objects.get(email=options['user'])
            qs = qs.filter(user = user)
        else:
            user=None

        if options['proto']:
            qs = qs.filter(proto = options['proto'])

        for ar in qs.all():
            now = timezone.now()
            print("[{}] {} {}".format(
                ar.reduction,
                dhms(ar.release_time - now) if ar.release_time is not None else '-',
                ar))
            if options['delete']:
                ar.delete()

