from django.conf.urls import url
from django.views.generic import TemplateView

from moveauth import views

app_name = 'moveauth'

urlpatterns = [
    url(r'^mkticket$', views.mkticket, name='index'),
    url(r'^land/(?P<ticket>[^/]+)/(?P<url>.*)', views.land, name='land')
]
