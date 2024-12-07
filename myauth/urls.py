#from django.conf.urls import patterns, url
# from django.conf.urls import url
from django.urls import path


from myauth import views


app_name = 'myauth'

urlpatterns = [
    #    url(r'^$', views.index, name='index'),
    path('login',views.login, name='login'),
    path('demologin',views.demologin, name='demologin'),
    path('logout',views.logout, name='logout'),
    path('signup',views.signup, name='signup'),
    path('recover',views.recover, name='recover'),
    path('verify',views.verify, name='verify'),
    path('profile',views.profile, name='profile'),
    path('error',views.error, name='error'),
#    url(r'^verify/(?P<email>[^\/]+)/(?P<code>[A-Z0-9a-z]+)?$',views.verify, name='verify'),
]

