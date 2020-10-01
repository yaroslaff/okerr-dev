#from django.conf.urls import patterns, url
from django.conf.urls import url
from django.views.generic import TemplateView

from okerrui import views, training


app_name = 'okerrui'

urlpatterns = [

    url('^oauth2/login/(?P<provider>[^/]+)(?P<suffix>.*)', views.oauth2_login, name='oauth2_login'),
    url('^oauth2/bind/(?P<provider>[^/]+)(?P<suffix>.*)', views.oauth2_bind, name='oauth2_bind'),
    url('^oauth2/callback', views.oauth2_callback, name='oauth2_callback'),
    url('^oauth2/select', views.oauth2_select, name='oauth2_select'),
    # url(r'oauth2/info/(<?P<provider>[^/]+)', views.oauth2_info, name='oauth2_info'),


    url(r'^sredir/(?P<name>[^/]+)/(?P<path>.*)', views.sredir, name='sredir'),

    url(r'afterlogin', views.afterlogin, name='afterlogin'),
    url(r'^$', views.index, name='index'),
    url(r'^sendsummary/(?P<textid>.+)', views.sendsummary, name='sendsummary'),
#    url(r'^setvpid/(?P<vpid>\d+)$', views.setvpid, name='setvpid'),
#    url(r'^setnovpid$', views.setvpid, name='setnovpid'),
    url(r'^$', views.index, name='index'),
#    url(r'^indicator/(?P<iid>\d+)$',views.indicator,name='indicator'),
    url(r'^indicator/(?P<iid>\d+)/ds$', views.indicator_ds, name='indicatords'),

    url(r'^i/(?P<pid>[^/]+)/(?P<iid>.+)$', views.ilocator, name='ilocator'),
    url(r'^i/(?P<iid>[^@]+)@(?P<pid>.+)$', views.ilocator, name='ilocatorat'),
    url(r'^i/(?P<textid>[^/]+)/?', views.pi, name='pi'),
#    url(r'^uptimelog/(?P<textid>[^/]+)/(?P<iname>.+)$',views.uptimelog,name='uptimelog'),

    url(r'^chproject', views.chproject, name='chproject'),

    url(r'^log/(?P<textid>[^/]+)$', views.project_log, name='project_log_nocode'),
    url(r'^log/(?P<textid>[^/]+)/(?P<codelist>.*)$', views.project_log, name='project_log'),


    url(r'^servers/(?P<pid>[^/]+)/?$',views.servers,name='servers'),

    # url(r'^servers/(?P<pid>[^/]+)/(?P<prepath>[^/]*)/(?P<path>[^/]+)',views.srvedit, name='srvedit'),
    url(r'^servers/(?P<pid>[^/]+)/(?P<prepath>[^/]*)/(?P<path>.+)', views.srvedit, name='srvedit'),

    url(r'^add/(?P<tid>.+)', views.add, name='add'),
    url(r'^doop/(?P<textid>.+)', views.doop, name='doop'),
    url(r'^invitations', views.invitations, name='invitations'),
    url(r'^acceptinvite', views.acceptinvite, name='acceptinvite'),
#    url(r'^policylist/?',views.policylist,name='policylist'),
    url(r'^policy/(?P<textid>[^/]+)/(?P<pname>.+)', views.policy, name='policy'),
    url(r'^projectlist/?', views.projectlist, name='projectlist'),
    url(r'^project/(?P<pid>.+)', views.project, name='project'),
    url(r'^pjson/(?P<pid>.+)', views.pjson, name='pjson'),
    url(r'^pdsjson/(?P<textid>[^/]+)/(?P<iname>.+)', views.pdsjson, name='pdsjson'),
    url(r'^rawpjson/(?P<tid>.+)', views.rawpjson, name='rawpjson'),
    url(r'^rawijson/(?P<iid>\d+)', views.rawijson, name='rawijson'),
    url(r'^keys/(?P<pid>[^/]+)/(?P<parentpath>.*)', views.keys, name='keys'),
    url(r'^keystext/(?P<pid>\d+)/(?P<parentpath>.*)', views.keystext, name='keystext'),
    url(r'^updatevkeys/(?P<pid>\d+)', views.updatevkeys, name='updatevkeys'),
    url(r'^resetkeys/(?P<pid>\d+)', views.resetkeys, name='resetkeys'),
    url('^toggle_interface_level/(?P<path>.+)', views.toggle_interface_level, name='toggle_interface_level'),

    #    url(r'^getkeytree/(?P<textid>[^\/]+)/(?P<path>.*)',views.getkeytree,name='getkeytree'),
    url(r'^exportkeyval/(?P<pid>[^\/]+)/(?P<path>.*)', views.exportkeyval, name='exportkeyval'),
    url(r'^exportkeyval_raw/(?P<pid>[^\/]+)/(?P<path>.*)', views.exportkeyval_raw, name='exportkeyval_raw'),

    url(r'^getnotifications', views.getnotifications, name='getnotifications'),
    url(r'^delnotification', views.delnotification, name='delnotification'),

#
#
    url(r'^wiznoflap/(?P<textid>[^/]+)/(?P<iname>.+)$', views.wiznoflap, name='wiznoflap'),
    url(r'^getsysvar/(?P<varname>.*)', views.getsysvar, name='getsysvar'),


    url(r'^getkeyval/(?P<textid>[^\/]+)/(?P<path>.*)', views.getkeyval, name='getkeyval'),
#    url(r'^getkeylist/(?P<textid>[^\/]+)/(?P<path>.*)',views.getkeylist,name='getkeylist'),
    url(r'^update/?', views.update, name='update'),
    url(r'^mirror/?', views.mirror, name='mirror'),
    url(r'^getpub/?', views.getpub, name='getpub'),
    url(r'^eula', views.eula, name='eula'),
    url(r'^motd', views.motd, name='motd'),
    url('^firstlogin', views.firstlogin, name='firstlogin'),
    url(r'^afterlife', views.afterlife, name='afterlife'),
    url(r'^bonusverify', views.bonusverify, name='bonusverify'),
    url(r'^tview', TemplateView.as_view(template_name='okerrui/eula.html')),
    url(r'^cat', views.cat, name='cat'),



    #
    # # # MODULES # # #
    #

    # STATUSPAGE
    url(r'^status/(?P<textid>[^/]+)/(?P<addr>.*)', views.status, name='status'),
    url(r'^jstatus/(?P<textid>[^/]+)/(?P<addr>.*)', views.jstatus, name='jstatus'),
    url(r'^statuspage/(?P<textid>[^/]+)/(?P<addr>.*)', views.statuspage, name='statuspage'),
    url(r'^statussubscribe/(?P<textid>[^/]+)/(?P<addr>[^/]+)/(?P<date>[^/]+)/(?P<email>[^/]+)/(?P<code>.+)',
        views.statussubscribe, name='statussubscribe'),
    url(r'^statusunsubscribe/(?P<textid>[^/]+)/(?P<addr>[^/]+)/(?P<date>[^/]+)/(?P<email>[^/]+)/(?P<code>.+)',
        views.statusunsubscribe, name='statusunsubscribe'),



    # TRAINING
    url(r'training/(?P<code>.*)', training.training, name='trainingcode'),
    url(r'training', training.training, name='training'),

    # DYNDNS
    url(r'dyndns/(?P<textid>[^/]+)/(?P<name>.*)', views.dyndns, name='dyndns'),


#    url(r'^project_backup/(?P<pid>\d+)?', views.project_backup, name='project_backup'),
#    url(r'^email_backup/(?P<pid>\d+)?', views.email_backup, name='email_backup'),





    ### API ###

    url(r'^api/indicators/(?P<pid>[^/]+)/?$', views.api_indicators, name='api_indicators'),
    url(r'^api/indicators/(?P<pid>[^/]+)/(?P<prefix>.+)', views.api_prefix, name='api_prefix'),
#    url(r'^api/getiname/(?P<pid>.+)/(?P<idname>.*)', views.api_getiname, name='api_getiname'),
#    url(r'^api/getiid/(?P<pid>.+)/(?P<idname>.*)', views.api_getiid, name='api_getiid'),
    url(r'^api/filter/(?P<pid>[^/]+)/(?P<kvlist>.*)', views.api_filter, name='api_filter'),
    url(r'^api/tagfilter/(?P<pid>[^/]+)/(?P<tagline>.*)?', views.api_tagfilter, name='api_tagfilter'),
    url(r'^api/indicator/(?P<pid>[^/]+)/(?P<iid>.+)', views.api_indicator, name='api_indicator'),
    url(r'^api/set/(?P<pid>[^/]+)/(?P<iid>.+)', views.api_set, name='api_set'),
    url(r'^api/get/(?P<pid>[^/]+)/(?P<iid>.+)/(?P<argname>.+)', views.api_get, name='api_getarg'),
    url(r'^api/create/(?P<pid>[^/]+)/(?P<iname>.+)', views.api_create, name='api_create'),
    url(r'^api/delete/(?P<pid>[^/]+)/(?P<iname>.+)', views.api_delete, name='api_delete'),
    url(r'^api/checkmethods', views.api_checkmethods, name='api_checkmethods'),
    url(r'^api/recheck/(?P<pid>[^/]+)/?$', views.api_recheck, name='api_recheck'),

    url(r'^api/director/(?P<textid>.*)', views.api_director, name='api_director'),
    url(r'^api/check_version/(?P<product>[^/]+)/(?P<version>.+)', views.api_check_version, name='api_check_version'),

    # compatibility aliases
    url(r'^api/getarg/(?P<pid>[^/]+)/(?P<iid>.+)/(?P<argname>.+)', views.api_get, name='api_get'),
    url(r'^api/setarg/(?P<pid>[^/]+)/(?P<iid>.+)', views.api_set, name='api_set'),

    ### Partner API ####
    url(r'^api/partner/check/(?P<partner_id>.+)', views.api_partner_check, name='api_partner_check'),
    url(r'^api/partner/list', views.api_partner_list, name='api_partner_list'),
    url(r'^api/partner/create', views.api_partner_create, name='api_partner_create'),
    url(r'^api/partner/grant', views.api_partner_grant, name='api_partner_grant'),
    url(r'^api/partner/revoke', views.api_partner_revoke, name='api_partner_revoke'),

#    url(r'^api/partner/preconfigure', views.api_partner_preconfigure, name='api_partner_preconfigure'),


    ### Private API ###
#    url(r'^api/sync/?(?P<tstamp>\d+)?', views.api_sync, name='api_sync'),
#    url(r'^api/fsync/?(?P<opts>.*)', views.api_fsync, name='api_fsync'),
    url(r'^api/plist', views.api_plist, name='api_plist'),
    url(r'^api/profile/(?P<pid>.+)', views.api_profile, name='api_profile'),
    url(r'^api/myprofile', views.api_myprofile, name='api_myprofile'),

    # url(r'^api/project/(?P<tid>.+)', views.api_project, name='api_project'),
#    url(r'^api/sdump/?(?P<srid>.+)?', views.api_sdump, name='api_sdump'),
    url(r'^api/tproc/get', views.api_tproc_get, name='api_tproc_get'),
    url(r'^api/tproc/set', views.api_tproc_set, name='api_tproc_set'),
    url(r'^api/listcluster', views.api_listcluster, name='api_listcluster'),
    url(r'^api/hostinfo', views.api_hostinfo, name='api_hostinfo'),
    url('^api/ip', views.api_ip, name='api_ip'),
    url(r'^api/status', views.api_status, name='api_status'),
#    url(r'^api/summary', views.api_summary, name='api_summary'),
    url(r'^api/setci$', views.api_setci, name='api_setci'),
    url(r'^api/groups', views.api_groups, name='api_groups'),
    url(r'^api/test', views.api_test, name='api_test'),


    url(r'^api/admin/list$', views.api_admin_list, name='api_admin_list'),
    url(r'^api/admin/cilist$', views.api_admin_cilist, name='api_admin_cilist'),
    url(r'^api/admin/export/(?P<email>.*)', views.api_admin_export, name='api_admin_export'),
    url(r'^api/admin/member/(?P<email>.*)', views.api_admin_member, name='api_admin_member'),
    url(r'^api/admin/accept_invite', views.api_admin_accept_invite, name='api_admin_accept_invite'),

    url(r'^api/admin/tglink', views.api_admin_tglink, name='api_admin_tglink'),
    url(r'^api/admin/qsum/(?P<textid>.*)', views.api_admin_qsum, name='api_admin_qsum'),
    url(r'^api/admin/chat_id/(?P<chat_id>.*)', views.api_admin_chat_id, name='api_admin_chat_id'),

    url(r'^api/admin/force_sync', views.api_admin_force_sync, name='api_admin_force_sync'),
    url(r'^api/admin/log/?(?P<mname>[^/]*)/?(?P<start>.*)', views.api_admin_log, name='api_admin_log'),

]
