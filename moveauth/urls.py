from django.urls import path, re_path
from django.views.generic import TemplateView

from moveauth import views

app_name = 'moveauth'

urlpatterns = [
    path(r'mkticket', views.mkticket, name='index'),
    re_path(r'^land/(?P<ticket>[^/]+)/(?P<url>.*)', views.land, name='land')
]
