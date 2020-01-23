from django.http import HttpResponse
from django.shortcuts import redirect
from okerrui.models import SystemVariable

class IPControlMiddleware:
    def process_request(self,request):
        if request.path.startswith('/admin/'):
            if request.user.is_authenticated():
                if request.user.is_staff:
                    # allowed
                    return None
                else:
                    return HttpResponse('zzz')
            else:
                return HttpResponse('zzz')
        else:
            # not protected section
            return None
