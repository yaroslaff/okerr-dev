from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from django.conf import settings

import oauth2_provider
# import okerr.settings_oauth

import json
from pprint import pprint

from okerrui.cluster import RemoteServer


class Command(BaseCommand):
    help = 'okerr oauth2 management'

    fields = ['name', 'client_id', 'client_secret', 'skip_authorization', 'redirect_uris', 'client_type', 'authorization_grant_type' ]


    def add_arguments(self,parser):
        parser.add_argument('--list', default=False, action='store_true', help='list all applications')
        parser.add_argument('--dump', default=False, action='store_true', help='dump --app')
        parser.add_argument('--export', default=False, action='store_true', help='export --app')
        parser.add_argument('--exportall', default=False, action='store_true', help='export all apps')
        parser.add_argument('--reinit', default=False, action='store_true', help='reinit from from OAUTH2_CLIENTS')

#        parser.add_argument('--user', default=None, help='list all applications')
        parser.add_argument('--app', default=None, help='application name')
        parser.add_argument('--skip', default=None, type=int, help='skip authorization')


    def reinit(self):
        # no need to reinit anything in db
        app_model = oauth2_provider.models.get_application_model()

        if not hasattr(settings, 'OAUTH2_CLIENTS'):
            print("skip reinit OAUTH2 because not configured (usually this is OK)")
            return

        User = get_user_model()
        app_model.objects.all().delete()
    
        appd = settings.OAUTH2_CLIENTS
        
        app = app_model()
        app.user = None
        for f in self.fields:
            setattr(app, f, appd[f])
                        
        # generate redirect_uris
        redirect_uris = ''

        # allsrv = settings.CLUSTER + ['cp.okerr.com']



        for rs in RemoteServer.all_rs():                       
            url = rs.url+'oauth2/callback'
            print(url)
            redirect_uris += url+'\r\n'

        app.redirect_uris = redirect_uris                
        app.save()
                        
    
    def export(self, app):
        d = dict()
        
        for f in self.fields:
            d[f] = getattr(app, f, None)
        return d
    
    def exportall(self):
        u = dict()
        app_model = oauth2_provider.models.get_application_model()

        for a in app_model.objects.all():
            if not a.user.email in u:
                u[a.user.email] = list() 
        
            u[a.user.email].append(self.export(a))
        
        #print json.dumps(u, indent=4)
        pprint(u)
    

    def dump(self, app):
        print("{}: {}".format(app.user, app.name))
        print("id:", app.client_id)
        print("secret:", app.client_secret)
        print("skip:", app.skip_authorization)


    def handle(self, *args, **options):
        
        # User = get_user_model()
        app_model = oauth2_provider.models.get_application_model()
        if options['app']:
            app = app_model.objects.get(name=options['app'])
        
                            
        if options['list']:
            print("list:")
            for a in app_model.objects.all():
                print(a.name, a.user)
        elif options['reinit']:
            self.reinit()
        elif options['dump']:
            self.dump(app)
        elif options['export']:
            d = self.export(app)        
            print(json.dumps(d, indent=4))
        elif options['exportall']:
            self.exportall()        
        elif options['skip'] is not None:
            app.skip_authorization = options['skip']
            app.save()
            self.dump(app)
