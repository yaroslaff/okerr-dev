#from django.conf.urls import patterns, url
from django.conf.urls import url


from myauth import views


app_name = 'myauth'

urlpatterns = [
    #    url(r'^$', views.index, name='index'),
    url(r'^login/?$',views.login, name='login'),
    url(r'^demologin/?$',views.demologin, name='demologin'),
    url(r'^logout/?$',views.logout, name='logout'),
    url(r'^signup/?$',views.signup, name='signup'),
    url(r'^recover/?$',views.recover, name='recover'),
    url(r'^verify/?$',views.verify, name='verify'),
    url(r'^profile/?$',views.profile, name='profile'),
    url(r'^error/?$',views.error, name='error'),
#    url(r'^verify/(?P<email>[^\/]+)/(?P<code>[A-Z0-9a-z]+)?$',views.verify, name='verify'),
]

