from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from logmessage.models import Logger, LogMessage

class Command(BaseCommand):
    help = 'LogMessage management'

    def add_arguments(self,parser):
        parser.add_argument('--list', action='store_true', help='list all LogMessages')
        parser.add_argument('--machine', default=None, help='machine name')
        parser.add_argument('--wipe', action='store_true', default=False, help='wipe all LogMessages')
        parser.add_argument('--log', default=None, help='write new log message')
        parser.add_argument('--kind', default='', help='kind of log message')
        parser.add_argument('--really', default=False, action='store_true', help='really. (for dangerous operations)')

    def handle(self, *args, **options):

        if options['list']:
            for lm in LogMessage.objects.order_by('created'):
                print lm
            return

        if options['log'] is not None:
            logger = Logger(options['machine'] or settings.HOSTNAME)
            logger.log(options['log'], kind=options['kind'])
