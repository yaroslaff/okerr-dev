#!/usr/bin/env python
from django.core.management.base import BaseCommand, CommandError
from okerrui.models import ProjectInvite
from django.contrib.auth import get_user_model
from django.utils import timezone
from myutils import dhms

class Command(BaseCommand):
    help = 'Manage alert records'
    
    def __init__(self):
        super(Command,self).__init__()

    def add_arguments(self,parser):                

        #parser.add_argument('--user', metavar='EMAIL', default=None, help='User by email')
        #parser.add_argument('--id', default=None, help='indicator ID')
        #parser.add_argument('--delete', default=False, action='store_true', help='indicator ID')
        parser.add_argument('--list', default=False, action='store_true', help='list invites')
        parser.add_argument('--delete', metavar='INVITE', help='delete by id or email')
        parser.add_argument('--send', metavar='INVITE', help='send email')


    def get_invite(self, invite_spec):
        try:
            invite_id = int(invite_spec)
            print("delete by id", invite_id)
            return ProjectInvite.objects.get(id=invite_id)
            
        except ValueError as e:
            email = invite_spec
            print("delete by email", email)
            return ProjectInvite.objects.get(email=invite_spec)


    def handle(self, *args, **options):
        User = get_user_model()

        # qs = ProjectInvite.objects

        if options['list']:
            print("List invites")
            for i in ProjectInvite.objects.all():
                print(f'#{i.id} {i}')

        elif options['delete']:
            try:
                i = self.get_invite(options['delete'])
            except ProjectInvite.DoesNotExist:
                print("Not found")
            else:                
                print("DELETE", i)
                i.delete()
        elif options['send']:
            try:
                i = self.get_invite(options['send'])
            except ProjectInvite.DoesNotExist:
                print("Not found")
            else:                
                i.send()

