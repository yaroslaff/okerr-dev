from django.shortcuts import get_object_or_404, render, redirect
from django.utils.translation import ugettext_lazy as _, pgettext
from django.utils.translation import to_locale, get_language
from django.contrib.auth.decorators import login_required
from django.urls import resolve, reverse
from django.db.models import Q, Sum, Max, Min
import re
from okerrui.bonuscode import BonusCode
from okerrui.views import notify

######
#
# Training
#
#####

tasks = {'basic':
    (
        {
            'code': 'pingok',
            'title': _(u'Ping OK'),
        },
        {
            'code': 'pingerr',
            'title': _(u'Ping ERR'),
        },

        {
            'code': 'sha',
            'title': _(u'Monitor web page'),
        },

        {
            'code': 'telegram',
            'title': _(u'Connect to Telegram'),
        },

        {
            'code': 'massdelete',
            'title': _(u'Delete group of indicators'),
        },

        {
            'code': 'okerrclient',
            'title': _(u'Install okerrclient'),
        },

        {
            'code': 'checkserver',
            'title': _(u'Check whole server'),
        },

        {
            'code': 'serverconf',
            'title': _(u'Special server configuration'),
        },

        {
            'code': 'policyactive',
            'title': _('Policy for active indicators'),
        },

        {
            'code': 'policypassive',
            'title': _('Policy for passive indicators'),
        },

        {
            'code': 'escalation',
            'title': _('Escalation'),
        },

        {
            'code': 'status',
            'title': _('Status page'),
        },

        {
            'code': 'failover',
            'title': _('Failover'),
        },

        {
            'code': 'DONE',
            'title': _('Training completed'),
        },
    )
}


@login_required(login_url='myauth:login')
def training(request, code=None):

    def get_stages(profile):
        stages = dict()
        if not profile.training_stage:
            return stages # empty array

        for ss in profile.training_stage.split(' '):
            try:
                section, stage = ss.split(':')
                stages[section] = stage
            except ValueError:
                pass
        return stages


    def get_stage(profile, section, code=None):
        """
            return stage or none (for new)
        """
        stagelist = [ t['code'] for t in tasks[section] ]
        defstage = tasks[section][0]['code']

        if code:
            if code in stagelist:
                return code
            else:
                return defstage

        stages = get_stages(profile)

        try:
            stage = stages[section]
        except KeyError:
            profile.training_stage = section + ':' + defstage
            profile.save()
            return defstage

        if not stages[section] in stagelist:
            return defstage

        return stage

    def set_stage(profile, section, stage):
        s = dict()
        tsstr = ''
        if profile.training_stage:
            pass

        s[section] = stage
        for k,v in s.items():
            tsstr += '{}:{}'.format(k,v)
        profile.training_stage = tsstr

    def get_task(section, code):
        for t in tasks[section]:
            if t['code'] == code:
                return t
        return None

    def get_test_project(profile):
        return profile.user.project_set.first()

    def check(profile, code):
        p = get_test_project(profile)

        def inotify(i, msg):
            notify(request, i.name + ': ' + str(msg))

        if code not in ['telegram', 'massdelete', 'serverconf']:
            if p.indicator_set.filter(name__startswith='test:').count() == 0:
                notify(request, _('no "test:*" indicators in project {}').format(p))
                return False

        if code not in ['telegram', 'massdelete']:
            if p.indicator_set.count() == 0:
                notify(request, _('no indicators in project {}').format(p))
                return False



        if code == 'pingok':

            for i in p.indicator_set.filter(name__startswith='test:'):
                if i.cm.codename != 'ping':
                    inotify(i, _("check method not '{}'").format('ping'))
                    continue

                if i.getarg('host') != '8.8.8.8':
                    inotify(i, _("host not 8.8.8.8"))
                    continue

                if i.mtime > i.updated:
                    inotify(i, _("check was not performed yet"))
                    continue

                if i._status != 'OK':
                    inotify(i, _("status not OK"))
                    continue

                if i.maintenance:
                    inotify(i, _("maintenance mode"))
                    continue
                # all checks passed
                return True

            # all indicators failed
            return False


        if code == 'pingerr':
            for i in p.indicator_set.filter(name__startswith='test:'):
                if i.cm.codename != 'ping':
                    inotify(i, _("check method not '{}'".format('ping')))
                    continue

                if i.mtime > i.updated:
                    inotify(i, _("check was not performed yet"))
                    continue

                if i._status != 'ERR':
                    inotify(i, _("status not ERR"))
                    continue

                if i.maintenance:
                    inotify(i, _("maintenance mode"))
                    continue

                # all checks passed
                return True

        if code == 'sha':
            for i in p.indicator_set.filter(name__startswith='test:'):
                if i.cm.codename != 'sha1dynamic':
                    inotify(i, _("check method not '{}'").format('sha1dynamic'))
                    continue

                if i._status != 'OK':
                    inotify(i, _("status not OK"))
                    continue

                if not i.getarg('hash'):
                    inotify(i, _("hash not initialized"))
                    continue

                return True


        if code == 'telegram':
            if not profile.telegram_name:
                notify(request, str(_("Telegram username not set in profile")))
                return False

            if not profile.telegram_chat_id:
                notify(request, str(_("Telegram not linked with {}").format(profile.telegram_name)))
                return False
            return True

        if code == 'massdelete':
            n = p.logrecord_set.filter(message__contains='deleted (masscmd)').count()
            if n<3:
                notify(request, str(_("{} indicators were mass-deleted recently").format(n)))
                return False
            return True

        if code == 'okerrclient':
            for i in p.indicator_set.filter(name__startswith='test:'):
                for lr in i.logrecord_set.filter(message__startswith='ALERT:autocreated from'):
                    return True

        if code == 'checkserver':
            for i in p.indicator_set.all():
                if not i.keypath:
                    inotify(i, _("Indicator was set not via server check"))
                    continue
                else:
                    return True


        if code == 'serverconf':
            for i in p.indicator_set.all():

                if i.keypath is None:
                    continue

                if not i.keypath.startswith('test'):
                    inotify(i, _("Indicator was not set from test* template"))
                    continue
                else:
                    return True

            return False

        if code == 'policyactive':
            for i in p.indicator_set.filter(name__startswith='test:'):
                policy = i.policy
                if not policy.name.startswith('test'):
                    inotify(i, _("Indicator uses policy {} (not test*)").format(policy.name))
                    continue

                if policy.get_period() != 7200:
                    inotify(i, _("Indicator policy {} period {} (not 2h)").format(policy.name, policy.period))
                    continue

                if policy.get_retry_schedule() != [300]:
                    inotify(i, _("Indicator policy {} retry schedule {} (not 5min)").format(policy.name, policy.retry_schedule))
                    continue

                if policy.get_retry_schedule(recovery = True):
                    inotify(i, _("Indicator policy {} recovery retry schedule {} (not emtpy)").format(policy.name, policy.recovery_retry_schedule))
                    continue

                if policy.autocreate:
                    inotify(i, _("Indicator policy {} has autocreate enabled").format(policy.name))
                    continue

                if policy.httpupdate:
                    inotify(i, _("Indicator policy {} has httpupdate enabled").format(policy.name))
                    continue

                if policy.smtpupdate:
                    inotify(i, _("Indicator policy {} has smtpupdate enabled").format(policy.name))
                    continue

                return True

        if code == 'policypassive':
            for i in p.indicator_set.filter(name__startswith='test:'):

                policy = i.policy

                if not i.cm.passive():
                    inotify(i, _("Not passive checkmethod").format(policy.name))
                    continue

                if not policy.name.startswith('test'):
                    inotify(i, _("Indicator uses policy {} (not test*)").format(policy.name))
                    continue

                if not policy.autocreate:
                    inotify(i, _("Policy {} has disabled autocreate").format(policy.name))
                    continue

                if not policy.secret:
                    inotify(i, _("Policy {} has no secret").format(policy.name))
                    continue

                if i.mtime > i.updated:
                    inotify(i, _("check was not performed yet"))
                    continue

                return True

        if code == 'escalation':
            ntest = 0
            for i in p.indicator_set.filter(name__startswith='test:'):
                if 'test' in i.tags():
                    ntest += 1

            if not ntest:
                notify(request, _('no test:* indicators with tag "test" in project'))
                return False

            if p.indicator_set.filter(name__startswith='test:', cm__codename='logic').count() == 0:
                notify(request, _('no logical indicator with name test:* in project'))
                return False

            for i in p.indicator_set.filter(name__startswith='test:', cm__codename='logic'):
                expr = i.getarg('expr')

                if i.mtime > i.updated:
                    inotify(i, _("check was not performed yet"))
                    continue

                if i.problem:
                    inotify(i,_("has problem flag"))
                    continue

                if not expr.startswith('age') or not 'test:uerrage' in expr:
                    inotify(i, _("has wrong expr"))
                    continue

                return True

        if code == 'status':

            if not p.statuspage_set.count():
                notify(request, _('no status pages in project'))

            for sp in p.statuspage_set.all():
                if not sp.public:
                    notify(request, _('status page {} not public').format(sp.addr))
                    continue

                if sp.statusindicator_set.count() < 2:
                    notify(request, _('status page {} has less then 2 indicators').format(sp.addr))
                    continue

                if not sp.statusblog_set.count():
                    notify(request, _('status page {} has no blog records').format(sp.addr))
                    continue
                return True

        if code == 'failover':
            if not p.dyndnsrecord_set.count():
                notify(request, _('No failover configured in project'))
                return False

            for ddr in p.dyndnsrecord_set.all():
                # get max prio
                maxprio = ddr.dyndnsrecordvalue_set.aggregate(Max('priority'))['priority__max']
                if ddr.indicators().count() < 2:
                    notify(request, _('Failover {} uses less then 2 indicators').format(ddr.hostname))
                    continue

                if not ddr.curvalue:
                    notify(request, _('Failover {} not initialized yet').format(ddr.hostname))
                    continue


                if ddr.curpriority == maxprio:
                    notify(request, _('Failover {} not switched to backup server').format(ddr.hostname))
                    continue

                if ddr.status_age()[0] != 'synced':
                    notify(request, _('Failover {} not synced yet. Retry little later.').format(ddr.hostname))
                    continue

                return True



        return False

    def next_stage(profile, section):
        stagelist = [ t['code'] for t in tasks[section] ]
        stage = get_stage(profile,'basic')
        if stage != 'DONE':
            next = stagelist[ stagelist.index(stage) + 1 ]
            set_stage(profile, section, next)
            return next
        return stage


    def get_task_number(section, code):
        num = 1
        for t in tasks[section]:
            if t['code'] == code:
                return num
            num += 1

    section = 'basic'
    ctx = dict()
    profile = request.user.profile
    project = get_test_project(profile)
    stage = get_stage(profile,'basic', code)

    if project is None:
        notify(request, _("You have to create at least one project for training"))
        return redirect("okerr:index")

#    basic = ['shahabr','maintenance','silent', 'delete']

    task = get_task(section, stage)

    if request.POST:
        if check(profile, stage):
            old_stage = stage
            stage = next_stage(profile, section)
            if stage == 'DONE':
                out = BonusCode.use('ReleasePromo2019', profile, apply=True)
                notify(request, out)
            else:
                notify(request, _('Training stage "{}" completed!').format(old_stage))

            profile.save()

        if 'return_uri' in request.POST:
            return redirect(request.POST['return_uri'])

        return redirect(request.path)


    ctx['project'] = project
    ctx['pname'] = project.name
    ctx['stage'] = stage
    ctx['tasks'] = list(tasks[section])
    ctx['n'] = get_task_number(section, stage)
    ctx['total'] = len(tasks[section])
    ctx['textid'] = project.get_textid()
    ctx['plink'] = reverse('okerr:pi', kwargs = {'textid': project.get_textid()})
    ctx['pconfig'] = reverse('okerr:project', kwargs = {'pid': project.get_textid()})
    ctx['tasktitle'] = task['title']
    ctx['style'] = dict()
    ctx['taskfile'] = 'okerrui/training/{}/{}.html'.format(get_language(), stage)
    completed = True

    for t in ctx['tasks']:
        ts = t['code']
        if ts == stage:
            t['class']='training-active'

            completed = False
        else:
            if completed:
                t['class'] = 'training-completed'
            else:
                t['class'] = 'training-todo'

    return render(request, 'okerrui/training/training.html', ctx)
