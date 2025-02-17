#!/usr/bin/env python3

import argparse
import pwd
import os
import sys
import subprocess
import shutil
import socket
import pwd
import urllib.request

# mydir = os.path.dirname(os.path.realpath(__file__))
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

logrotate /var/log/okerr/*log
"""


def myip():

    headers = {'User-Agent': 'curl/6.6.6'}

    for url in ['https://cp.okerr.com/api/ip', 'https://diagnostic.opendns.com/myip',
                'https://ifconfig.me/', 'https://ifconfig.io/',
                'http://cp.okerr.com/api/ip', 'http://diagnostic.opendns.com/myip',
                'http://ifconfig.me/', 'http://ifconfig.io/']:

        try:
            req = urllib.request.Request(
                url,
                data=None,
                headers=headers
            )

            ip = urllib.request.urlopen(req).read().decode('ascii')

            socket.inet_aton(ip)
            print("Got my IP {} via {}".format(ip, url))
            return ip

        except Exception as e:
            continue


def copy_template(src, dst, tokens):
    with open(src, "r") as srcf:
        with open(dst, "w") as dstf:
            data = srcf.read()
            for token, value in tokens.items():
                data = data.replace(token, value)
            dstf.write(data)


def systemd(command, daemon=None):
    if command in ['restart', 'start', 'stop', 'enable', 'disable']:
        rc = subprocess.run(['systemctl', command, daemon])
        if rc.returncode == 0:
            print("systemd {} {}".format(command, daemon))
        else:
            print("failed systemd {} {}".format(command, daemon))
            assert (rc.returncode == 0)

    elif command in ['daemon-reload']:
        rc = subprocess.run(['systemctl', command])
        if rc.returncode == 0:
            print("systemd {}".format(command))
        else:
            print("failed to systemd{}".format(command))
            assert (rc.returncode == 0)


def test_rsyslogd(args):
    basename = '20-okerr.conf'
    srcpath = os.path.join(mydir, 'contrib/etc/rsyslog.d/', basename)
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
    assert (os.path.exists(confpath))

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
        with open(confpath, "a") as f:
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

        with open(rcpath, "w") as f:
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
    localconf_path = os.path.join(localconf_dir, 'local.d', 'local.conf')
    copyfiles = [
        ('contrib/etc/okerr/okerr.conf', 'okerr.conf'),
        ('contrib/etc/okerr/json/keys-template.json', 'json/keys-template.json'),
        ('contrib/etc/okerr/env/netprocess', 'env/netprocess'),
        ('contrib/etc/okerr/env/sensor', 'env/sensor'),
        ('contrib/etc/okerr/env/mqsender', 'env/mqsender'),
    ]

    if args.rmq:
        copyfiles.append(('contrib/etc/rabbitmq/rabbitmq.config', '/etc/rabbitmq/rabbitmq.config'))

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

        else:
            print("[LOCALCONF NO {}]".format(localconf_path))
            return False

        for fsrc, fdst in copyfiles:
            src = os.path.join(mydir, fsrc)
            dst = os.path.join(localconf_dir, fdst)
            print("make local config", dst)
            copy_template(src, dst, tokens)

    return True

def test_confd(args):

    if args.confd is None:
        # no confd
        return True

    for d in args.confd:

        assert(os.path.isdir(d))

        link = os.path.join('/etc/okerr/', os.path.basename(d))

        if os.path.exists(link):
            print("[CONFD {} exists]".format(link))
        else:
            if args.fix:
                print("[CONFD {}]".format(link))
                os.symlink(os.path.realpath(d), link)
            else:
                return False

    return True

def test_systemd(args):
    services_dir = '/etc/systemd/system'
    orig_services_dir = os.path.join(mydir, 'contrib/etc/systemd/system')
    services = ['okerr.service',
                'okerr-netprocess.service', 'okerr-poster.service', 'okerr-process.service', 'okerr-smtpd.service',
                'okerr-telebot.service', 'okerr-ui.service', 'okerr-mqsender.service']

    services_custom = [
        ('okerr-sensor.service', os.path.join(args.venv, 'okerrsensor/okerr-sensor-venv.service'),
         '/etc/systemd/system/okerr-sensor.service')
    ]

    for service in services:
        src = os.path.join(orig_services_dir, service)
        dst = os.path.join(services_dir, service)
        services_custom.append((service, src, dst))

    ok = True

    print("[SYSTEMD ...]")

    for service, src, dst in services_custom:
        if os.path.exists(dst) and not args.overwrite:
            print("already exists {} and no --overwrite".format(dst))
            continue

        if args.fix:
            print("Make {}".format(dst))

            copy_template(src, dst, tokens)

            systemd('daemon-reload')
            systemd('enable', service)
            # restarted in postinstall
            # systemd('restart', service)
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
        cmdline = ['mariadb', '-u', 'root']
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
                manage = os.path.join(sys.path[0], 'manage.py')
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
        if (args.fix):
            print("create user {} home {}".format(args.user, args.home))
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
    src = os.path.join(mydir, './contrib/etc/apache2/sites-available/okerr.conf')
    dst = '/etc/apache2/sites-available/okerr.conf'

    commands = [
        ['a2enmod', 'proxy'],
        ['a2enmod', 'proxy_uwsgi'],
        ['a2ensite', 'okerr'],
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
            copy_template(src, dst, tokens)
            for cmd in commands:
                print(' '.join(cmd))
                rc = subprocess.run(cmd)
                assert (rc.returncode == 0)
            systemd('restart', 'apache2')
        else:
            return False

    return True


def test_deb_packages(args):
    packages = [
        'git',
        'pkg-config',
        'python3-dev',
        'python3-venv',
        'dialog',
        'gcc',
        # 'libmysqlclient-dev',
        # 'libmariadbclient-dev',  # debian 9
        # 'libmariadb-dev-compat', # debian 10
        'libmariadb-dev', # debian 11?
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
        packages.extend(['apache2', 'libapache2-mod-proxy-uwsgi'])

    if args.rmq:
        print("RMQ specific configuration")
        packages.append('rabbitmq-server')

    if args.fix or args.overwrite:
        os.system('apt update')
        cmdline = 'DEBIAN_FRONTEND=noninteractive apt install -qy {}'.format(' '.join(packages))
        os.system(cmdline)
        return True
    else:
        cmdline = 'dpkg -l {} > /dev/null'.format(' '.join(packages))
        code = os.system(cmdline) >> 8
        if (code):
            print('Some packages are missing. Use --fix to install')
            return False
        else:
            print("All required packages are installed")

    return True


def test_okerrupdate(args):
    okerrmod = os.path.join(args.venv, 'bin/okerrmod')

    if os.path.exists('/etc/okerr/okerrupdate') and not args.overwrite:
        print("already exists /etc/okerr/okerrupdate config")
    elif args.fix:
        cmd = [okerrmod, '--init', '--url', 'http://localhost.okerr.com/', '--direct', '--textid', 'okerr']
        subprocess.run(cmd)
    else:
        print("missing okerrupdate config!")
        return False

    return True


def test_postinstall(args):
    print("[POSTINSTALL]")
    python3 = os.path.join(args.venv, 'bin/python3')
    manage = os.path.join(sys.path[0], 'manage.py')

    # check if user exists (optional)

    if args.email:
        cmd = [python3, manage, 'profile', '--user', args.email]
        user_exist = subprocess.run(cmd).returncode == 0

        if user_exist:
            print("postinstall: user {} already exists".format(args.email))

        elif args.fix:
            print("create okerr user", args.email)
            cmd = [python3, manage, 'profile', '--create', args.email, '--pass', args.password, '--textid', 'okerr']
            subprocess.run(cmd)

            print("grant admin to user", args.email)
            cmd = [python3, manage, 'group', '--assign', 'Admin', '--user', args.email, '--infinite']
            subprocess.run(cmd)
        else:
            print("User {} not exists!".format(args.email))
            return False

    services_list = ['okerr']

    if args.rmq:
        services_list.insert(0, 'rabbitmq-server')

    if args.fix:
        for srv in services_list:
            systemd('restart', srv)

    return True


def test_ca(args):
    mkcert = os.path.join(sys.path[0], 'ca', 'mkcert.sh')
    cwd = os.path.join(sys.path[0], 'ca')
    path = '/etc/okerr/ssl'

    print("[CA]")

    if not os.path.exists(path):
        os.mkdir(path)

    code = 'ca'
    if os.path.exists('/etc/okerr/ssl/{}.pem'.format(code)) and not args.overwrite:
        print("Already exists {}.pem".format(code))
    elif args.fix:
        print("Generate SSL certificates")
        cmd = [mkcert, 'ca']
        subprocess.run(cmd, cwd=cwd)
    else:
        print("Certificates {} not found".format(code))
        return False

    clientcode = ['client']
    if args.rmq:
        clientcode.append('rabbitmq')

    for code in clientcode:
        if os.path.exists('/etc/okerr/ssl/{}.pem'.format(code)) and not args.overwrite:
            print("Already exists {}.pem".format(code))
        elif args.fix:
            print("Generate SSL certificates")
            cmd = [mkcert, 'client', code]
            subprocess.run(cmd, cwd=cwd)
        else:
            print("Certificates {} not found".format(code))
            return False

    return True


def test_sanity(args):
    # if args.run in ['all', 'postinstall'] and (args.email is None or args.password is None):
    #    print("Need email and password for 'postinstall' check")
    #    return False

    return True


def test_rabbitmq(args):
    rabbitmqctl = '/usr/sbin/rabbitmqctl'

    if not args.rmq:
        print("[RABBITMQ skipped]")
        return True

    # check
    rc = subprocess.run([rabbitmqctl, 'list_permissions', '-p', 'okerr'])
    if rc.returncode == 0 and not args.overwrite:
        print("[RABBITMQ vhost exists]")
        return True

    cmdlist = [
        [rabbitmqctl, 'add_vhost', 'okerr'],
        [rabbitmqctl, 'add_user', 'okerr', 'okerr'],
        [rabbitmqctl, 'set_permissions', '-p', 'okerr', 'okerr', '.*', '.*', '.*']
    ]

    for cmd in cmdlist:
        print("RUN:", ' '.join(cmd))
        subprocess.run(cmd)

    return True


tests = ['sanity', 'deb', 'user', 'venv', 'python', 'okerrupdate', 'localconf', 'confd', 'dbadmin', 'redis',
         'rsyslogd', 'ca',
         'rabbitmq', 'bashrc', 'apache', 'uwsgi', 'systemd', 'postinstall']

def_venv = '/opt/venv/okerr'
def_varrun = '/var/run/okerr'
def_wwwgroup = 'www-data'

def_rmquser = os.getenv('RMQ_USER', 'okerr')
def_rmqpass = os.getenv('RMQ_PASS', 'okerr')
def_rmqhost = os.getenv('RMQ_HOST', '127.0.0.1')
def_rmqvhost = os.getenv('RMQ_VHOST', 'okerr')
def_sensor = os.getenv('SENSOR_NAME', 'okerr-dev@local.ru')

parser = argparse.ArgumentParser(description='Okerr installer')

parser.add_argument('--fix', default=False, action='store_true', help='Fix problems, not just report')
parser.add_argument('--skip', nargs='*', default=list())
parser.add_argument('--run', metavar='CHECK', default='all',
                    help='Run just one check. "all" or one of: {}'.format(str(tests)))
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
g.add_argument('--varrun', default=def_varrun, metavar='DIR',
               help='path to /var/run/NAME directory. def: {}'.format(def_varrun))


g = parser.add_argument_group('Cluster-specific')
g.add_argument('--host', default=list(), nargs='+', help='my hostnames')
g.add_argument('--cluster', default='LOCAL', help='Cluster name')
g.add_argument('--confd', nargs='*', help='Link to this configuration directory')
g.add_argument('--sensor', default=def_sensor, help='sensor name ({})'.format(def_sensor))
g.add_argument('--rmqhost', default=def_rmqhost, help='RabbitMQ host ({})'.format(def_rmqhost))
g.add_argument('--rmqvhost', default=def_rmqvhost, help='RabbitMQ virtual host ({})'.format(def_rmqvhost))
g.add_argument('--rmquser', default=def_rmquser, help='RabbitMQ user ({})'.format(def_rmquser))
g.add_argument('--rmqpass', default=def_rmqpass, help='RabbitMQ pass ({})'.format(def_rmqpass))


g = parser.add_argument_group('Installation variants')
g.add_argument('--local', default=False, action='store_true',
               help='Typical local-server install: --apache --rmq --fix --overwrite '
                    '--user okerr@example.com --pass okerr_default_password')
g.add_argument('--apache', default=False, action='store_true', help='install apache2 and integrate with it')
g.add_argument('--rmq', default=False, action='store_true', help='install RabbitMQ server')

g = parser.add_argument_group('Installation post-config option')
g.add_argument('--email', default=None, metavar='EMAIL')
g.add_argument('--pass', dest='password', default=None, metavar='PASSWORD')

args = parser.parse_args()

# process typical install method
if args.local:
    args.apache = True
    args.host = ['localhost.okerr.com', 'dev.okerr.com']
    args.rmq = True
    args.fix = True
    args.overwrite = True
    args.password = args.password or 'okerr_default_password'

if not args.host:
    print("No host addresses given, use --host FQDN1 FQDN2 ...")
    sys.exit(1)

tokens = {
    '%OKERR%': mydir,
    '%VENV%': args.venv,
    '%user%': args.user,
    '%group%': args.group,
    '%varrun%': args.varrun,

    '%MYIP%': myip(),
    '%EMAIL%': args.email,
    '%CLUSTER%': args.cluster,
    '%HOSTS%': str(args.host),

    '%HOSTNAME%': args.host[0].split('.')[0],
    '%FQDN%': args.host[0],
    '%SERVERALIASES%': ' '.join(args.host[1:]),

    '%RMQ_USER%': args.rmquser,
    '%RMQ_PASS%': args.rmqpass,
    '%RMQ_HOST%': args.rmqhost,
    '%RMQ_VHOST%': args.rmqvhost,

    '%SENSOR%': args.sensor
}

testmap = {
    'sanity': test_sanity,
    'user': test_user,
    'deb': test_deb_packages,
    'venv': test_venv,
    'python': test_python,
    'dbadmin': test_dbadmin,
    'systemd': test_systemd,
    'redis': test_redis,
    'bashrc': test_bashrc,
    'localconf': test_localconf,
    'confd': test_confd,
    'rsyslogd': test_rsyslogd,
    # 'varrun': test_varrun,
    'uwsgi': test_uwsgi,
    'apache': test_apache,
    'ca': test_ca,
    'rabbitmq': test_rabbitmq,
    'okerrupdate': test_okerrupdate,
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
