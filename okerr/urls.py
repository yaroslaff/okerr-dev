#from django.conf.urls import patterns, include, url
#from django.conf.urls import include, url
from django.urls import path, re_path, include

#from emailusernames.forms import EmailAuthenticationForm
from django.contrib import admin
admin.autodiscover()
import okerrui.views

from django.conf import settings

#urlpatterns = patterns('',
#    # Examples:
#    url(r'^$',okerrui.views.index),
#    url(r'^okerr/',include('okerrui.urls',namespace='okerr')),
#    url(r'^auth/',include('myauth.urls',namespace='myauth')),
#    url(r'^admin/', include(admin.site.urls)),
#    url(r'^i18n/', include('django.conf.urls.i18n')),
#)



urlpatterns = [
    # Examples:
    re_path(r'^$', okerrui.views.index),
    #url(r'^okerr/',include('okerrui.urls' ,namespace='okerr')),
    re_path(r'', include('myauth.urls', namespace='myauth')),
    #url(r'^auth/',include('myauth.urls',namespace='myauth')),
    #re_path(r'^admin/', include(admin.site.urls)),
    # path(r'admin/', admin.site.urls),
    re_path(r'^i18n/', include('django.conf.urls.i18n')),
    re_path(r'', include('okerrui.urls' ,namespace='okerr')),
    # url('', include('social_django.urls', namespace='social')),
    re_path(r'moveauth/', include('moveauth.urls' , namespace='moveauth')),
    re_path(r'^o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
]

if settings.DEBUG:
    import debug_toolbar
    urlpatterns = [
        path('__debug__/', include(debug_toolbar.urls)),
    ] + urlpatterns
    from django.conf.urls.static import static
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

