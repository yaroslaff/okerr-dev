
from django.shortcuts import redirect
from okerrui.models import SystemVariable

class EULAMiddleware:
    def process_request(self,request):
        noeula = ['/okerr/eula','/auth/logout','/i18n/setlang/']

        if request.user.is_authenticated:
            if request.path in noeula:
                return None
            if request.user.profile.eula_accepted():
                return None
            else:
                return redirect('okerr:eula')
        else:
            # not logged user
            pass
        return None
