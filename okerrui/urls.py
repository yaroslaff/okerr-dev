#from django.conf.urls import patterns, url
# from django.conf.urls import url
from django.urls import path,re_path

from django.views.generic import TemplateView

from okerrui import views, training


app_name = 'okerrui'

urlpatterns = [

    re_path('oauth2/login/(?P<provider>[^/]+)(?P<suffix>.*)', views.oauth2_login, name='oauth2_login'),
    re_path('oauth2/bind/(?P<provider>[^/]+)(?P<suffix>.*)', views.oauth2_bind, name='oauth2_bind'),
    path('oauth2/callback', views.oauth2_callback, name='oauth2_callback'),
    path('oauth2/select', views.oauth2_select, name='oauth2_select'),
    # url(r'oauth2/info/(<?P<provider>[^/]+)', views.oauth2_info, name='oauth2_info'),


    re_path(r'^sredir/(?P<name>[^/]+)/(?P<path>.*)', views.sredir, name='sredir'),

    path(r'afterlogin', views.afterlogin, name='afterlogin'),
    path(r'', views.index, name='index'),
    re_path(r'^sendsummary/(?P<textid>.+)', views.sendsummary, name='sendsummary'),
#    url(r'^setvpid/(?P<vpid>\d+)$', views.setvpid, name='setvpid'),
#    url(r'^setnovpid$', views.setvpid, name='setnovpid'),
    # url(r'^$', views.index, name='index'),
#    url(r'^indicator/(?P<iid>\d+)$',views.indicator,name='indicator'),
    re_path(r'^indicator/(?P<iid>\d+)/ds$', views.indicator_ds, name='indicatords'),

    re_path(r'^i/(?P<pid>[^/]+)/(?P<iid>.+)$', views.ilocator, name='ilocator'),
    re_path(r'^i/(?P<iid>[^@]+)@(?P<pid>.+)$', views.ilocator, name='ilocatorat'),
    re_path(r'^i/(?P<textid>[^/]+)/?', views.pi, name='pi'),
#    url(r'^uptimelog/(?P<textid>[^/]+)/(?P<iname>.+)$',views.uptimelog,name='uptimelog'),

    path(r'chproject', views.chproject, name='chproject'),

    re_path(r'^log/(?P<textid>[^/]+)$', views.project_log, name='project_log_nocode'),
    re_path(r'^log/(?P<textid>[^/]+)/(?P<codelist>.*)$', views.project_log, name='project_log'),




    re_path(r'^servers/(?P<pid>[^/]+)/?$',views.servers,name='servers'),

    # re_path(r'^servers/(?P<pid>[^/]+)/(?P<prepath>[^/]*)/(?P<path>[^/]+)',views.srvedit, name='srvedit'),
    re_path(r'^servers/(?P<pid>[^/]+)/(?P<prepath>[^/]*)/(?P<path>.+)', views.srvedit, name='srvedit'),

    re_path(r'^add/(?P<tid>.+)', views.add, name='add'),
    re_path(r'^doop/(?P<textid>.+)', views.doop, name='doop'),
    re_path(r'^invitations', views.invitations, name='invitations'),
    re_path(r'^acceptinvite', views.acceptinvite, name='acceptinvite'),
#    re_path(r'^policylist/?',views.policylist,name='policylist'),
    re_path(r'^policy/(?P<textid>[^/]+)/(?P<pname>.+)', views.policy, name='policy'),
    re_path(r'^projectlist/?', views.projectlist, name='projectlist'),
    re_path(r'^project/(?P<pid>.+)', views.project, name='project'),
    re_path(r'^pjson/(?P<pid>.+)', views.pjson, name='pjson'),
    re_path(r'^pdsjson/(?P<textid>[^/]+)/(?P<iname>.+)', views.pdsjson, name='pdsjson'),
    re_path(r'^rawpjson/(?P<tid>.+)', views.rawpjson, name='rawpjson'),
    re_path(r'^rawijson/(?P<iid>\d+)', views.rawijson, name='rawijson'),
    re_path(r'^keys/(?P<pid>[^/]+)/(?P<parentpath>.*)', views.keys, name='keys'),
    re_path(r'^keystext/(?P<pid>\d+)/(?P<parentpath>.*)', views.keystext, name='keystext'),
    re_path(r'^updatevkeys/(?P<pid>\d+)', views.updatevkeys, name='updatevkeys'),
    re_path(r'^resetkeys/(?P<pid>\d+)', views.resetkeys, name='resetkeys'),
    re_path('^toggle_interface_level/(?P<path>.+)', views.toggle_interface_level, name='toggle_interface_level'),

    #    re_path(r'^getkeytree/(?P<textid>[^\/]+)/(?P<path>.*)',views.getkeytree,name='getkeytree'),
    re_path(r'^exportkeyval/(?P<pid>[^\/]+)/(?P<path>.*)', views.exportkeyval, name='exportkeyval'),
    re_path(r'^exportkeyval_raw/(?P<pid>[^\/]+)/(?P<path>.*)', views.exportkeyval_raw, name='exportkeyval_raw'),

    re_path(r'^getnotifications', views.getnotifications, name='getnotifications'),
    re_path(r'^delnotification', views.delnotification, name='delnotification'),

#
#
    re_path(r'^wiznoflap/(?P<textid>[^/]+)/(?P<iname>.+)$', views.wiznoflap, name='wiznoflap'),
    re_path(r'^getsysvar/(?P<varname>.*)', views.getsysvar, name='getsysvar'),


    re_path(r'^getkeyval/(?P<textid>[^\/]+)/(?P<path>.*)', views.getkeyval, name='getkeyval'),
#    re_path(r'^getkeylist/(?P<textid>[^\/]+)/(?P<path>.*)',views.getkeylist,name='getkeylist'),
    re_path(r'^update/?', views.update, name='update'),
    re_path(r'^mirror/?', views.mirror, name='mirror'),
    re_path(r'^getpub/?', views.getpub, name='getpub'),
    re_path(r'^eula', views.eula, name='eula'),
    re_path(r'^motd', views.motd, name='motd'),
    re_path('^firstlogin', views.firstlogin, name='firstlogin'),
    re_path(r'^afterlife', views.afterlife, name='afterlife'),
    re_path(r'^bonusverify', views.bonusverify, name='bonusverify'),
    re_path(r'^tview', TemplateView.as_view(template_name='okerrui/eula.html')),
    re_path(r'^cat', views.cat, name='cat'),



    #
    # # # MODULES # # #
    #

    # STATUSPAGE
    re_path(r'^status/(?P<textid>[^/]+)/(?P<addr>.*)', views.status, name='status'),
    re_path(r'^jstatus/(?P<textid>[^/]+)/(?P<addr>.*)', views.jstatus, name='jstatus'),
    re_path(r'^statuspage/(?P<textid>[^/]+)/(?P<addr>.*)', views.statuspage, name='statuspage'),
    re_path(r'^statussubscribe/(?P<textid>[^/]+)/(?P<addr>[^/]+)/(?P<date>[^/]+)/(?P<email>[^/]+)/(?P<code>.+)',
        views.statussubscribe, name='statussubscribe'),
    re_path(r'^statusunsubscribe/(?P<textid>[^/]+)/(?P<addr>[^/]+)/(?P<date>[^/]+)/(?P<email>[^/]+)/(?P<code>.+)',
        views.statusunsubscribe, name='statusunsubscribe'),



    # TRAINING
    re_path(r'training/(?P<code>.*)', training.training, name='trainingcode'),
    re_path(r'training', training.training, name='training'),

    # DYNDNS
    re_path(r'dyndns/(?P<textid>[^/]+)/(?P<name>.*)', views.dyndns, name='dyndns'),


#    re_path(r'^project_backup/(?P<pid>\d+)?', views.project_backup, name='project_backup'),
#    re_path(r'^email_backup/(?P<pid>\d+)?', views.email_backup, name='email_backup'),





    ### API ###

    re_path(r'^api/indicators/(?P<pid>[^/]+)/?$', views.api_indicators, name='api_indicators'),
    re_path(r'^api/indicators/(?P<pid>[^/]+)/(?P<prefix>.+)', views.api_prefix, name='api_prefix'),
#    re_path(r'^api/getiname/(?P<pid>.+)/(?P<idname>.*)', views.api_getiname, name='api_getiname'),
#    re_path(r'^api/getiid/(?P<pid>.+)/(?P<idname>.*)', views.api_getiid, name='api_getiid'),
    re_path(r'^api/filter/(?P<pid>[^/]+)/(?P<kvlist>.*)', views.api_filter, name='api_filter'),
    re_path(r'^api/tagfilter/(?P<pid>[^/]+)/(?P<tagline>.*)?', views.api_tagfilter, name='api_tagfilter'),
    re_path(r'^api/updatelog/(?P<pid>[^/]+)/(?P<iid>.+)', views.api_updatelog, name='api_updatelog'),
    re_path(r'^api/indicator/(?P<pid>[^/]+)/(?P<iid>.+)', views.api_indicator, name='api_indicator'),
    
    re_path(r'^api/set/(?P<pid>[^/]+)/(?P<iid>.+)', views.api_set, name='api_set'),
    re_path(r'^api/get/(?P<pid>[^/]+)/(?P<iid>.+)/(?P<argname>.+)', views.api_get, name='api_getarg'),
    re_path(r'^api/create/(?P<pid>[^/]+)/(?P<iname>.+)', views.api_create, name='api_create'),
    re_path(r'^api/delete/(?P<pid>[^/]+)/(?P<iname>.+)', views.api_delete, name='api_delete'),
    re_path(r'^api/checkmethods', views.api_checkmethods, name='api_checkmethods'),
    re_path(r'^api/recheck/(?P<pid>[^/]+)/?$', views.api_recheck, name='api_recheck'),

    re_path(r'^api/director/(?P<textid>.*)', views.api_director, name='api_director'),
    re_path(r'^api/check_version/(?P<product>[^/]+)/(?P<version>.+)', views.api_check_version, name='api_check_version'),

    # compatibility aliases
    re_path(r'^api/getarg/(?P<pid>[^/]+)/(?P<iid>.+)/(?P<argname>.+)', views.api_get, name='api_get'),
    re_path(r'^api/setarg/(?P<pid>[^/]+)/(?P<iid>.+)', views.api_set, name='api_set'),

    ### Partner API ####
    re_path(r'^api/partner/check/(?P<partner_id>.+)', views.api_partner_check, name='api_partner_check'),
    re_path(r'^api/partner/list', views.api_partner_list, name='api_partner_list'),
    re_path(r'^api/partner/create', views.api_partner_create, name='api_partner_create'),
    re_path(r'^api/partner/grant', views.api_partner_grant, name='api_partner_grant'),
    re_path(r'^api/partner/revoke', views.api_partner_revoke, name='api_partner_revoke'),

#    re_path(r'^api/partner/preconfigure', views.api_partner_preconfigure, name='api_partner_preconfigure'),


    ### Private API ###
#    re_path(r'^api/sync/?(?P<tstamp>\d+)?', views.api_sync, name='api_sync'),
#    re_path(r'^api/fsync/?(?P<opts>.*)', views.api_fsync, name='api_fsync'),
    re_path(r'^api/plist', views.api_plist, name='api_plist'),
    re_path(r'^api/profile/(?P<pid>.+)', views.api_profile, name='api_profile'),
    re_path(r'^api/myprofile', views.api_myprofile, name='api_myprofile'),

    # re_path(r'^api/project/(?P<tid>.+)', views.api_project, name='api_project'),
#    re_path(r'^api/sdump/?(?P<srid>.+)?', views.api_sdump, name='api_sdump'),
    re_path(r'^api/tproc/get', views.api_tproc_get, name='api_tproc_get'),
    re_path(r'^api/tproc/set', views.api_tproc_set, name='api_tproc_set'),
    re_path(r'^api/listcluster', views.api_listcluster, name='api_listcluster'),
    re_path(r'^api/hostinfo', views.api_hostinfo, name='api_hostinfo'),
    re_path('^api/ip', views.api_ip, name='api_ip'),
    re_path(r'^api/status', views.api_status, name='api_status'),
#    re_path(r'^api/summary', views.api_summary, name='api_summary'),
    re_path(r'^api/setci$', views.api_setci, name='api_setci'),
    re_path(r'^api/groups', views.api_groups, name='api_groups'),
    re_path(r'^api/test', views.api_test, name='api_test'),


    re_path(r'^api/admin/list$', views.api_admin_list, name='api_admin_list'),
    re_path(r'^api/admin/cilist$', views.api_admin_cilist, name='api_admin_cilist'),
    re_path(r'^api/admin/export/(?P<email>.*)', views.api_admin_export, name='api_admin_export'),
    re_path(r'^api/admin/member/(?P<email>.*)', views.api_admin_member, name='api_admin_member'),
    re_path(r'^api/admin/accept_invite', views.api_admin_accept_invite, name='api_admin_accept_invite'),

    re_path(r'^api/admin/tglink', views.api_admin_tglink, name='api_admin_tglink'),
    re_path(r'^api/admin/qsum/(?P<textid>.*)', views.api_admin_qsum, name='api_admin_qsum'),
    re_path(r'^api/admin/chat_id/(?P<chat_id>.*)', views.api_admin_chat_id, name='api_admin_chat_id'),

    re_path(r'^api/admin/force_sync', views.api_admin_force_sync, name='api_admin_force_sync'),
    re_path(r'^api/admin/log/?(?P<mname>[^/]*)/?(?P<start>.*)', views.api_admin_log, name='api_admin_log'),

]
