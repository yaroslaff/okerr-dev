#!/usr/bin/env python3

import argparse
import pwd
import os
import sys
import subprocess
import shutil
import grp
import pwd
import urllib.request

#mydir = os.path.dirname(os.path.realpath(__file__))
mydir = sys.path[0]

"""
TODO: SECRET_KEY
okerrupdate config
RMQ keys generate
install RMQ
install sensor
install adns @ git+https://github.com/trolldbois/python3-adns/
SERVER_EMAIL
ADMINS
disable netprocess
mkdir /var/log/okerr
"""

def myip():
    url = 'https://diagnostic.opendns.com/myip'
    return urllib.request.urlopen(url).read().decode('ascii')

def copy_template(src, dst, tokens):
    with open(src, "r") as srcf:
        with open(dst, "w") as dstf:
            data = srcf.read()
            for token, value in tokens.items():
                data = data.replace(token, value)
            dstf.write(data)


def systemd(command, daemon=None):

    if command in ['restart', 'enable', 'disable']:
        rc = subprocess.run(['systemctl', command, daemon])
        if rc.returncode == 0:
            print("systemd {} {}".format(command, daemon))
        else:
            print("failed systemd {} {}".format(command, daemon))
            assert(rc.returncode == 0)

    elif command in ['daemon-reload']:
        rc = subprocess.run(['systemctl', command])
        if rc.returncode == 0:
            print("systemd {}".format(command))
        else:
            print("failed to systemd{}".format(command))
            assert(rc.returncode == 0)


def test_rsyslogd(args):
    basename = '20-okerr.conf'
    srcpath = os.path.join(mydir,'contrib/etc/rsyslog.d/', basename)
    dstpath = os.path.join('/etc/rsyslog.d/', basename)

    if os.path.exists(dstpath) and not args.overwrite:
        print("[RSYSLOGD already configured]")
        return True

    if args.fix:
        print("[RSYSLOGD configured]")
        shutil.copy(srcpath, dstpath)
        systemd('restart', 'rsyslog')
        return True
    else:
        print("[RSYSLOGD not configured]")
        return False


def test_redis(args):
    confpath = '/etc/redis/redis.conf'
    assert(os.path.exists(confpath))

    with open(confpath) as f:
        conf = f.read()

    if '\nunixsocket' in conf:
        print("[REDIS unixsocket configured]")
        return True


    if args.fix:
        print("[REDIS configure unixsocket]")
        snippet = """
#
# OKERR requires unixsocket in redis
#

unixsocket /var/run/redis/redis.sock
unixsocketperm 770
"""
        with open(confpath,"a") as f:
            f.write(snippet)

        print("restart redis with new config")
        systemd('restart', 'redis')
        return True
    else:
        print("[REDIS unixsocket NOT configured]")
        return False


def test_bashrc(args):
    rcpath = os.path.join(mydir, '.bash_profile')
    print("check {}".format(rcpath))


    if os.path.exists(rcpath) and not args.overwrite:
        print("[BASHRC SKIP {} already exists]".format(rcpath))
        return True


    if args.fix:
        print("[BASHRC CREATE {}]".format(rcpath))
        data = ". {venv}/bin/activate\n".format(venv=args.venv)

        with open(rcpath,"w") as f:
            f.write(data)

        # set owner
        uid, gid = pwd.getpwnam(args.user).pw_uid, pwd.getpwnam(args.wwwgroup).pw_uid
        os.chown(rcpath, uid, gid)
        return True

    else:
        print("[BASHRC NO {}]".format(rcpath))
        return False

def test_localconf(args):
    localconf_dir = '/etc/okerr'
    localconf_subdirs = ['json', 'local.d', 'env']
    localconf_path = os.path.join(localconf_dir, 'local.d','local.conf')
    copyfiles = [
        ('contrib/etc/okerr/json/keys-template.json', 'json/keys-template.json'),
        ('contrib/etc/okerr/env/netprocess', 'env/netprocess')
    ]

    if os.path.exists(localconf_path) and not args.overwrite:
        print("[LOCALCONF SKIP {} exists]".format(localconf_path))
    else:
        if args.fix:
            print("[LOCALCONF CREATE {}]".format(localconf_path))
            if not os.path.isdir(localconf_dir):
                print("mkdir", localconf_dir)
                os.mkdir(localconf_dir)

            for subdir in localconf_subdirs:
                path = os.path.join(localconf_dir, subdir)
                if not os.path.isdir(path):
                    print("mkdir", path)
                    os.mkdir(path)

            allowed_hosts = ['localhost', '127.0.0.1', 'localhost.okerr.com', 'dev.okerr.com']
            allowed_hosts.extend(args.host)
            data = """ALLOWED_HOSTS = {allowed_hosts}
MYIP = '{myip}'
HOSTNAME = 'localhost'
SITEURL = 'http://{HOSTNAME}/'
""".format(allowed_hosts = allowed_hosts, myip = myip(), HOSTNAME='localhost')

            with open(localconf_path, "w") as f:
                f.write(data)
        else:
            print("[LOCALCONF NO {}]".format(localconf_path))
            return False

        for fsrc, fdst in copyfiles:
            src = os.path.join(mydir, fsrc)
            dst = os.path.join(localconf_dir, fdst)
            copy_template(src, dst, tokens)


    return True

def test_systemd(args):
    services_dir = '/etc/systemd/system'
    orig_services_dir = os.path.join(mydir, 'contrib/etc/systemd/system')
    services = ['okerr.service',
                'okerr-netprocess.service', 'okerr-poster.service',	'okerr-process.service', 'okerr-smtpd.service',
                'okerr-telebot.service', 'okerr-ui.service', 'okerr-mqsender.service']

    services_custom = [
        ('okerr-sensor.service', os.path.join(args.venv, 'okerrsensor/okerr-sensor-venv.service'), '/etc/systemd/system/okerr-sensor.service')
    ]

    for service in services:
        src = os.path.join(orig_services_dir, service)
        dst = os.path.join(services_dir, service)
        services_custom.append((service, src, dst))


    ok = True

    print("[SYSTEMD ...]")

    for service, src, dst in services_custom:
        # path = os.path.join(services_dir, service)
        if os.path.exists(dst) and not args.overwrite:
            print("already exists {} and no --overwrite".format(dst))
            continue

        if args.fix:
            print("Make {}".format(dst))

            copy_template(src, dst, tokens)

            systemd('daemon-reload')
            systemd('enable', service)
            systemd('start', service)
        else:
            print("No fix")
            ok = False

    return ok

def test_dbadmin(args):

    python3 = os.path.join(args.venv, 'bin/python3')

    def mysql_cmd(args, sql, dbname=None, stdout=None, stderr=None):
        # dbname = dbname or args.dbname
        cmdline = ['mariadb', '-u', args.dbuser, '-p' + args.dbpass, '-e', sql]
        if dbname:
            cmdline.append(args.dbname)
        rc = subprocess.run(cmdline, stdout=stdout, stderr=stderr)
        return rc.returncode

    def mysql_root_cmd(args, sql, dbname=None):
        cmdline = ['mariadb', '-u', 'root' ]
        if args.rootpass:
            cmdline.append('-p')
            cmdline.append(args.rootpass)
        cmdline.extend(['-e', sql])
        if dbname:
            cmdline.append(dbname)
        rc = subprocess.run(cmdline)
        return rc.returncode

    with open(os.devnull, 'w') as devnull:
        if mysql_cmd(args, sql='SELECT 1', dbname=args.dbname, stdout=devnull, stderr=devnull) != 0:
            if args.fix:
                print("[DBADMIN FIX: Create okerr database]")

                """
                CREATE DATABASE `okerr` CHARACTER SET utf8 COLLATE utf8_general_ci;
                GRANT ALL ON `okerr`.* TO `okerr`@`localhost` IDENTIFIED BY 'okerrpass';
                """

                sql_commands = [
                    "CREATE DATABASE {} CHARACTER SET utf8 COLLATE utf8_general_ci;".format(args.dbname),
                    "CREATE USER '{}'@'localhost' IDENTIFIED BY '{}';".format(args.dbuser, args.dbpass),
                    "GRANT ALL ON {}.* TO '{}'@'localhost';".format(args.dbname, args.dbuser)
                    ]

                for sql in sql_commands:
                    print("SQL: {}".format(sql))
                    mysql_root_cmd(args, dbname=None, sql=sql)

                # Apply migrations
                manage = os.path.join(sys.path[0],'manage.py')
                os.system('{} {} migrate'.format(python3, manage))
                os.system('{} {} dbadmin --reinit --really'.format(python3, manage))
                return True

            else:
                print("[DBADMIN No okerr user/database, use --fix to create]")
                return False
        else:
            print("[DBADMIN already exists]")
            # already exists
            return True

def test_python(args):
    reqs = os.path.join(mydir, 'requirements.txt')
    # adns = os.path.join(mydir, 'contrib/adns-1.4-py1.tar.gz')

    pip3venv = os.path.join(args.venv, 'bin/pip3')

    print("[PYTHON]")

    os.system('{} install wheel'.format(pip3venv))
    os.system('{} install -r {}'.format(pip3venv, reqs))
    # os.system('{} install {}'.format(pip3, adns))
    return True

def test_user(args):
    try:
        pwd.getpwnam(args.user)
        print("[USER {} exists]".format(args.user))
        return True
    except KeyError:
        print("[USER {} not exists]".format(args.user))
        if(args.fix):
            print("Create user {} home {}".format(args.user, args.home))
            os.system('useradd -r -m -G redis -d {} -s /bin/bash {}'.format(args.home, args.user))
            os.system('passwd -l {}'.format(args.user))
            return True
        else:
            print("use --fix to fix automatically")
            return False


def test_venv(args):
    if os.path.isdir(args.venv) and not args.overwrite:
        print("[VENV {} exists]".format(args.venv))
        return True
    else:
        if args.fix:
            print("[VENV CREATE]")
            os.system('python3 -m venv {}'.format(args.venv))
            return True
        else:
            print("[VENV]")
            print("no venv in {}, use --fix to create".format(args.venv))
            return False

def UNUSED_test_varrun(args):
    if os.path.isdir(args.varrun):
        print("[VARRUN {} exists]".format(args.varrun))
    else:
        if args.fix:
            print("[VARRUN create {}]".format(args.varrun))
            os.mkdir(args.varrun)
        else:
            print("[VARRUN]")
            print("No {} dir, use --fix to create".format(args.varrun))
            return False

    uid, gid = pwd.getpwnam(args.user).pw_uid, pwd.getpwnam(args.wwwgroup).pw_uid
    stat_info = os.stat(args.varrun)
    if stat_info.st_uid == uid and stat_info.st_gid == gid:
        print("Owner/group OK")
    else:
        if args.fix:
            shutil.chown(args.varrun, user=uid, group=gid)
            print("fixed user/group to {}:{}".format( args.user, args.wwwgroup ))
        else:
            print("User (need: {} real: {}). group ({}/{}) mismatch.".format(uid, stat_info.st_uid, gid, stat_info.st_gid))
            return False

    if stat_info.st_mode & 0o777 == 0o775:
        print("permissions are ok ({})".format(oct(stat_info.st_mode)))
    else:
        if args.fix:
            print("fix wrong permissions {}".format(oct(stat_info.st_mode)))
            os.chmod(args.varrun, 0o775)
        else:
            return False

    # all tests passed, either OK or fixed
    return True

def test_uwsgi(args):
    conffile = '/etc/okerr/uwsgi.ini'
    if os.path.isfile(conffile) and not args.overwrite:
        print("[UWSGI config file exists]")
        return True
    else:
        if args.fix:
            tpl_file = os.path.join(mydir, 'contrib/etc/okerr/uwsgi.ini')
            copy_template(tpl_file, conffile, tokens)
        else:
            print("[UWSGI missing config file]")
            return False
    return True


def test_apache(args):
    src = os.path.join(mydir,'./contrib/etc/apache2/sites-available/okerr.conf')
    dst = '/etc/apache2/sites-available/okerr.conf'

    commands = [
        ['a2enmod','proxy'],
        ['a2enmod','proxy_uwsgi'],
        ['a2ensite','okerr'],
    ]

    if not args.apache:
        # skip apache configs
        return True

    if os.path.exists(dst) and not args.overwrite:
        print("[APACHE okerr virtualhost exists]")
        return True
    else:
        if args.fix:
            print("[APACHE configure]")
            print(".. create virtual host")
            shutil.copy(src, dst)
            for cmd in commands:
                print(' '.join(cmd))
                rc = subprocess.run(cmd)
                assert(rc.returncode == 0)
            systemd('restart','apache2')
        else:
            return False

    return True

def test_deb_packages(args):
    packages=[
        'python3-dev',
        'python3-venv',
        'dialog',
        'gcc',
        #'libmysqlclient-dev',
        'libmariadbclient-dev', # debian 9
        # 'libmariadb-dev-compat', # debian 10
        'libadns1-dev',
        'libffi-dev',
        'libssl-dev',
        'libsasl2-modules',
        'redis-server',
        'redis-tools',
        'libadns1-dev',
        'mariadb-server',
        'rsyslog',
        'postfix',
        'cron'
    ]

    print("[DEB]")

    if args.apache:
        packages.extend(['apache2','libapache2-mod-proxy-uwsgi'])

    if args.fix or args.overwrite:
        os.system('apt update')
        cmdline = 'apt install {}'.format(' '.join(packages))
        os.system(cmdline)
        return True
    else:
        cmdline = 'dpkg -l {} > /dev/null'.format(' '.join(packages))
        code = os.system(cmdline) >> 8
        if(code):
            print('Some packages are missing. Use --fix to install')
            return False
        else:
            print("All required packages are installed")

    return True


def test_postinstall(args):
    print("test_postinstall")
    python3 = os.path.join(args.venv, 'bin/python3')
    okerrmod = os.path.join(args.venv, 'bin/okerrmod')
    manage = os.path.join(sys.path[0], 'manage.py')



    # check 1 okerr user

    # check if user exists

    cmd = [python3, manage, 'profile','--user', args.email]
    user_exist = subprocess.run(cmd).returncode == 0

    if user_exist:
        print("postinstall: user {} already exists".format(args.email))

    elif args.fix:
        print("create user", args.email)
        cmd = [python3, manage, 'profile', '--create', args.email, '--pass', args.password, '--textid', 'okerr']
        subprocess.run(cmd)

        print("grant admin to user", args.email)
        cmd = [python3, manage, 'group', '--assign', 'Admin', '--user', args.email, '--infinite']
        subprocess.run(cmd)
    else:
        print("User {} not exists!".format(args.email))
        return False

    # check 2 okerrupdate config

    if os.path.exists('/etc/okerr/okerrupdate'):
        print("already exists /etc/okerr/okerrupdate config")
    elif args.fix:
        cmd = [okerrmod,'--init', '--url', 'http://localhost/', '--direct', '--textid', 'okerr']
        subprocess.run(cmd)
    else:
        print("missing okerrupdate config!")
        return False

    return True


tests = ['deb', 'user', 'venv', 'python', 'dbadmin', 'redis', 'rsyslogd', 'systemd','bashrc', 'localconf', 'apache',
         'uwsgi','postinstall']

def_venv = '/opt/venv/okerr'
def_varrun = '/var/run/okerr'
def_wwwgroup = 'www-data'
parser = argparse.ArgumentParser(description='Okerr installer')

parser.add_argument('--fix', default=False, action='store_true', help='Fix problems, not just report')
parser.add_argument('--skip', nargs='?', default=list())
parser.add_argument('--run', metavar='CHECK', default='all', help='Run just one check. "all" or one of: {}'.format(str(tests)))
parser.add_argument('--overwrite', default=False, action='store_true', help='Overwrite (be careful)')

g = parser.add_argument_group('Options')
g.add_argument('--user', default='okerr', metavar='user')
g.add_argument('--group', default='okerr', metavar='group')
g.add_argument('--wwwgroup', default=def_wwwgroup, metavar='group', help='www group def: {}'.format(def_wwwgroup))
g.add_argument('--home', default='/opt/okerr', metavar='DIR')
g.add_argument('--rootpass', default=None, help='mariadb root pass')
g.add_argument('--dbname', default='okerr')
g.add_argument('--dbuser', default='okerr')
g.add_argument('--dbpass', default='okerrpass')
g.add_argument('--venv', default=def_venv, help='Path to virtualenv {}'.format(def_venv))
g.add_argument('--varrun', default=def_varrun, metavar='DIR', help='path to /var/run/NAME directory. def: {}'.format(def_varrun))
g.add_argument('--host', default=list(), nargs='+', help='my hostnames')
g.add_argument('--apache', default=False, action='store_true', help='install apache2 and integrate with it')

g = parser.add_argument_group('Installation post-config option')
g.add_argument('--email', default=None, required=True, metavar='EMAIL')
g.add_argument('--pass', dest='password', default=None, required=True, metavar='PASSWORD')


args = parser.parse_args()

tokens = {
    '%OKERR%': mydir,
    '%VENV%': args.venv,
    '%user%': args.user,
    '%group%': args.group,
    '%varrun%': args.varrun
}

testmap = {
    'user': test_user,
    'deb': test_deb_packages,
    'venv': test_venv,
    'python': test_python,
    'dbadmin': test_dbadmin,
    'systemd': test_systemd,
    'redis': test_redis,
    'bashrc': test_bashrc,
    'localconf': test_localconf,
    'rsyslogd': test_rsyslogd,
    # 'varrun': test_varrun,
    'uwsgi': test_uwsgi,
    'apache': test_apache,
    'postinstall': test_postinstall,
    # 'migrate': test_migrate
}

if args.run == 'all':
    for test in tests:
        if test in args.skip:
            print("Skipping test {}".format(test))
            continue

        print("")
        if not testmap[test](args):
            print("Stop after failed test {}".format(test))
            sys.exit(1)
else:
    testmap[args.run](args)
