from django.conf import settings

def my_settings(request):
    return {
        'MYMAIL_ADD_FOOTER': settings.MYMAIL_FOOTER,
        'HOSTNAME': settings.HOSTNAME
    }
    
