#!/usr/bin/env python
from django.core.management.base import BaseCommand, CommandError
from okerrui.models import Profile, Bonus, BonusActivation, BonusNotFound, BonusVerificationFailed
from django.contrib.auth import get_user_model
#from django.core.exceptions import ValidationError, ObjectDoesNotExist, PermissionDenied

class Command(BaseCommand):
    help = 'Apply bonus codes'

    def add_arguments(self, parser):

        g = parser.add_argument_group('Apply bonus codes')

        g.add_argument('--user', metavar='EMAIL', default=None, help='User by email')
        g.add_argument('--code', metavar='CODE', default=False, help='Enter bonus code for user')
        g.add_argument('--internal', action='store_true', default=False, help='Entered code is internal')

        g = parser.add_argument_group('Bonus codes')
        g.add_argument('--list', action='store_true', default=False, help='List bonus codes')
        g.add_argument('--show', metavar='NAME', default=False, help='Show one code')
        g.add_argument('--generate', default=None, metavar='NAME', help='Generate --num codes')
        g.add_argument('--verify', default=None, metavar='CODE', help='Verify code')

        g.add_argument('--num', '-n', type=int, default=10, metavar='NUM', help='How many codes to generate')
        g.add_argument('--value', default=None, metavar='VALUE', help='Value for code (or random)')

        g = parser.add_argument_group('Debug')
        g.add_argument('--cron', default=False, action='store_true', help='Run BonusActivation cron job')
        g.add_argument('--cronall', default=False, action='store_true',
                       help='Run BonusActivation cron job (for all activations)')
        g.add_argument('--delact', default=None, type=int, help='Delete activation record by id number')


    def handle(self, *args, **options):
        User = get_user_model()

        if options['list']:
            print("LIST")
            for name in Bonus.names():
                b = Bonus.get_by_name(name)
                print(b)

        if options['show']:
            b = Bonus.get_by_name(options['show'])
            b.dump()

        if options['user'] and options['code']:
            try:
                user = User.objects.get(email=options['user'])
                profile = Profile.objects.get(user=user)
            except ObjectDoesNotExist as e:
                print("No such user")
                return

            try:
                b = Bonus.get_by_code(options['code'], options['internal'])
            except BonusNotFound as e:
                print("No such bonus code")
                return

            try:
                b.apply(profile, options['code'])
            except ValueError as e:
                print("ERR:", e)

        if options['generate']:
            try:
                b = Bonus.get_by_name(options['generate'])
            except BonusNotFound as e:
                print("No such bonus code")
                return

            value = options['value']
            if value:
                n = 1
            else:
                n = options['num']

            for _ in range(n):
                print(b.generate(value=value))

        if options['verify']:
            try:
                b = Bonus.get_by_code(options['verify'])
            except BonusNotFound as e:
                print("No such bonus code")
                return
            try:
                b.verify(options['verify'])
                print("OK")
            except BonusVerificationFailed as e:
                print(e)

        if options['cron']:
            BonusActivation.cron()

        if options['cronall']:
            BonusActivation.cron(all_records=True)

        if options['delact']:
            ba = BonusActivation.objects.get(id=options['delact'])
            print("DELETE:", ba)
            print(ba.delete())