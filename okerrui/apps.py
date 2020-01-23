
# from django.db.models.signals import post_syncdb, pre_migrate, post_migrate
from django.db.models.signals import pre_migrate, post_migrate


#from django.contrib.auth.models import User
#from django.utils import timezone

# from models import Policy,Indicator,Profile,CheckMethod, CheckArg, CheckArgVal,Group,GroupArg
# from .bonuscode import BonusCode
#from django.core.exceptions import ObjectDoesNotExist
from django.apps import AppConfig
# import okerrui.models
#from django.conf import settings
#import datetime

#default_app_config='okerrui.OkErrUIAppConfig'

class okerruiApp(AppConfig):
    name='okerrui'


