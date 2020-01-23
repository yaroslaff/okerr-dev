#!/usr/bin/env python
from django.core.management.base import BaseCommand, CommandError
from okerrui.models import Project, DynDNSRecord, Profile
from django.contrib.auth import get_user_model


class Command(BaseCommand):
    help = 'Manage dyndns records'
    
    def __init__(self):
        super(Command,self).__init__()

    def add_arguments(self,parser):                

        parser.add_argument('--user', metavar='EMAIL', default=None, help='User by email')
        parser.add_argument('--textid', '-i', metavar='TEXTID', default=None, help='Project textid')
        parser.add_argument('--list', action='store_true', default=False, help='List dynamic records')

    def handle(self, *args, **options):
        User = get_user_model()

        if options['user']:
            user = User.objects.get(email=options['user'])
            profile = Profile.objects.get(user=user)
        else:
            user = None
            profile = None

        if options['list']:

            if user:
                qs = DynDNSRecord.objects.filter(project__owner=user)
            elif options['textid']:
                qs = DynDNSRecord.objects.filter(project__projecttextid__textid=options['textid'])
            else:
                qs = DynDNSRecord.objects.all()

            for ddr in qs:
                print(ddr)
