#!/usr/bin/env python
import os, sys, time
import logging, logging.handlers
import argparse, json
import datetime
import pika
import pika.exceptions
import ssl
from myutils import dt2unixtime, dhms, shorttime
import traceback
import redis
import socket

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "okerr.settings")
import django
from django.conf import settings

from django.utils import timezone

from dotenv import load_dotenv
import okerrupdate

# basic Django setup
django.setup()

from okerrui.cluster import myci
from okerrui.models import Project, Indicator

resultq = None
redis_conn = None
myindicator = None

class TProcExc(Exception):
    def __init__(self, textid=None, name=None):
        super().__init__()
        self.textid = textid
        self.name = name

    def __str__(self):
        return "{} {}@{}".format(self.__class__.__name__, self.name, self.textid)

    def data(self):
        return dict(exception=self.__class__.__name__,
                    textid=self.textid, name=self.name)


class TProcNoProject(TProcExc):
    pass

class TProcNoIndicator(TProcExc):
    pass

class TProcForgetIndicator(TProcExc):
    pass


def get_redis(redis_dbi=0):
    if 'REDIS_HOST' in os.environ:
        while True:
            try:
                return redis.Redis(host=os.environ['REDIS_HOST'], port=6379, db=redis_dbi)
            except redis.exceptions.ConnectionError as e:
                log.warning('Redis not ready. Sleep and retry...')
                time.sleep(1)
    else:
        rsocks = ['/var/run/redis/redis-server.sock', '/var/run/redis/redis.sock']

        for rs in rsocks:
            if os.path.exists(rs):
                r = redis.Redis(unix_socket_path=rs, decode_responses=True, db=redis_dbi)
                return r

def unlockold(td=None):
    #log.info('unlocking....')
    now=timezone.now()
    if not td:
        #log.debug('unlock all records')
        uq = Indicator.objects.filter(lockpid__isnull=False)
    else:
        #log.debug('unlock old locked records ({} ago)'.format(td))
        uq = Indicator.objects.filter(lockpid__isnull=False, lockat__lt=now-td)
    uc = uq.update(lockpid=None,lockat=None)
    log.debug("unlocked {} records".format(uc))

def lock(pid, numi=50):
    """
        lock numi records.
        we lock by setting lockpid to non-null (random) value.
        we cannot set to PID
        npname - netprocess name
    """
    now = timezone.now()

    remote = True

    # hostname = 'charlie'
    # hostname = settings.HOSTNAME

    my_ci = myci()

    # nested_q=Indicator.objects.filter(lockpid__isnull=True, ci=my_ci, problem=False, disabled=False, dead=False, deleted_at__isnull=True, scheduled__lte=now, cm__remote=remote).exclude(last_fail_machine=machine).values_list('pk', flat=True)[:numi]

    nested_q = Indicator.objects.filter(lockpid__isnull=True, ci=my_ci, problem=False, disabled=False, dead=False,
                                        deleted_at__isnull=True, scheduled__lte=now, cm__remote=remote).order_by(
        'scheduled').values_list('pk', flat=True)[:numi]

    nlocked = Indicator.objects.filter(pk__in=list(nested_q), lockpid__isnull=True, ci=my_ci, disabled=False,
                                       deleted_at__isnull=True, scheduled__lte=now, cm__remote=remote).update(
        lockpid=pid, lockat=now)
    return nlocked


def send_kill(ch, machine, reason='just die please'):
    ctlqname = machine['ctlq']

    ctldata = {
        '_task': 'tproc.kill',
        'pid': machine['pid'],
        'reason': reason
    }

    log.info("send kill {} to {}: {}".format(ctldata['pid'], machine['name'], reason))
    ch.basic_publish(
        exchange='',
        routing_key=ctlqname,
        body=json.dumps(ctldata))

def callback_return(ch, method, properties, body):
    log.warning('GOT returned message to {} ::: {}'.format(method, dir(method)))

def qkey(qname):
    # redis queue key name
    return 'okerr:sensor:queue:' + qname

def sensor_queue_exists(qname):
    return redis_conn.exists(qkey(qname))

def process_hello(data):
    name = data['_machine']['name']

    key = 'okerr:sensor:hello:{}'.format(name)
    redis_conn.set(key, data['uptime'])
    redis_conn.expire(key, 20)

    for qname in data['_machine']['qlist']:
        key = 'okerr:sensor:queue:'+qname
        redis_conn.set(key, name)
        redis_conn.expire(key, 20)

def get_other_machine_queue(name):
    # return q name for other machine or None
    for key in redis_conn.keys('okerr:sensor:queue:*'):
        if not '@' in key:
            continue
        if key.endswith(':'+name):
            continue

        qname = redis_conn.get(key)
        # first direct queue for other machine
        return qname

def process_tproc_reply(channel, data):

    name = data['_machine']['name']
    remoteip = data['_machine']['ip']

    now = timezone.now()

    project = Project.get_by_textid(data['textid'])
    if project is None:
        raise TProcNoProject(name = data['name'], textid=data['textid'])

    try:
        i = project.get_indicator(data['name'])
    except Indicator.DoesNotExist:
        raise TProcNoIndicator(name = data['name'], textid=data['textid'])

    if int(data['code']) == 200:
        if data['mtime'] == dt2unixtime(i.mtime):
            if i.expected:
                if data['status'] != i.status \
                        or now >= i.expected - datetime.timedelta(seconds=settings.MQ_PROCESS_TIME):

                    log.info('GET {}@{} = {} ({}) {}'.format(
                        data['name'], data['textid'],
                        data['status'], data['details'], name))

                    backlog = int(time.time() - i.expected.timestamp())
                    if backlog > 30:
                        log.debug("backlog: {}".format(dhms(backlog)))
                    i.apply_tproc(data, name, location=None, throttled=data.get('_throttled'))
                    log.debug("rescheduled: exp: {} sch: {}".format(
                        shorttime(i.expected), shorttime(i.scheduled)))
                    i.usave()
                else:
                    send_kill(channel, data['_machine'],
                              "Too early. now {} < exp: {}".format(
                                    now.strftime('%H:%M:%S'),
                                    i.expected.strftime('%H:%M:%S')))
            else:
                send_kill(channel, data['_machine'],
                          "Not expected update for {}@{}".format(data['name'], data['textid']))

        else:
            send_kill(channel, data['_machine'],
                      "Too old mtime {} ({})".format(data['mtime'], dt2unixtime(i.mtime) - data['mtime']))

    else:
        # code not 200
        log.info('apply_tproc_fail {} {} {}:"{}" {}@{} = {}'.format(
            name, remoteip,
            data['code'], data['code_message'],
            data['name'], data['textid'], data['status']))
        i.last_fail_machine = name
        i.log('Temprorary internal error ({}): {}. Do not worry.'.format(data['code'], data['code_message']))
        i.scheduled = timezone.now() + datetime.timedelta(seconds=settings.MQ_RETRY_TIME)
        i.usave()



def get_routing_key(i, data):
    """
        prepare data if needed, and return routing key
    """
    if i.is_quick():
        data['throttle'] = settings.MQ_THROTTLE_TIME
        qprefix = "tasksq:"
    else:
        qprefix="tasks:"

    if not i.location or not sensor_queue_exists(i.location):
        # if location not needed or not available
        if i.last_fail_machine:
            qname = get_other_machine_queue(i.last_fail_machine) or 'any'
            return qprefix + qname
        return qprefix + 'any'
    else:
        # available
        return qprefix + i.location


def mainloop(args):
    global redis_conn

    iupdate_last = time.time()
    iupdate_period = 600
    nput = 0
    nget = 0

    pid = os.getpid()
    redis_conn = get_redis(settings.OKERR_REDIS_DB)
    assert(redis_conn)

    credentials = pika.PlainCredentials(args.rmquser, args.rmqpass)
    context = ssl.create_default_context(cafile=args.capem)
    context.load_cert_chain(args.pem)
    ssl_options = pika.SSLOptions(context, "rabbitmq")

    properties=pika.BasicProperties(
        expiration=str(args.rmqttl*1000),
    )

    connection = pika.BlockingConnection(
        pika.ConnectionParameters(
            host=args.rmqhost, port=5671,
            virtual_host=args.rmqvhost,
            ssl_options=ssl_options,
            credentials=credentials))
    channel = connection.channel()

    channel.add_on_return_callback(callback_return)

    channel.queue_declare(queue='tasksq:any', auto_delete=True)
    channel.queue_declare(queue='tasks:any', auto_delete=True)

    # results queue name is random, unique to each mqsender
    rqname = 'results:{}:{}'.format(socket.gethostname(), os.getpid())
    hqname = 'hello:{}:{}'.format(socket.gethostname(), os.getpid())


    r = channel.queue_declare(queue=rqname, exclusive=True)
    resultq = r.method.queue
    log.info('Result queue name: {}'.format(resultq))

    channel.exchange_declare(exchange='hello_ex', exchange_type='fanout')
    helloq = channel.queue_declare(queue=hqname, exclusive=True).method.queue
    log.info('Hello queue name: {}'.format(helloq))

    channel.queue_bind(exchange='hello_ex', queue=helloq)


    while True:

        #
        # Part I: Send tasks
        #
        nlocked = lock(pid=pid)
        # log.debug("locked {} records".format(nlocked))
        if nlocked > 0:
            for i in Indicator.objects.filter(lockpid=pid):
                # print i,i.lockpid,i.lockat

                data = i.tproc()
                data['resultq'] = resultq

                i.expected = timezone.now()
                i.scheduled = timezone.now() + datetime.timedelta(seconds=settings.MQ_PROCESS_TIME)

                # we updated indicator, now unlock it
                i.lockpid = None
                i.lockat = None

                i.save()

                route = get_routing_key(i, data)

                channel.basic_publish(
                    exchange='',
                    routing_key=route,
                    body = json.dumps(data),
                    properties = properties)
                nput += 1

                log.info("PUT {}@{} ({})".format(i.name, i.project.get_textid(), route))
                log.debug("rescheduled: exp: {} sch: {}".format(
                    shorttime(i.expected), shorttime(i.scheduled)))


            # log.info('tproc/get request from {} {}@{} {}/{}'.format(remoteip,name,location, nlocked, len(data)))
        else:
            # log.info('tproc/get request from {} {}@{} nothing'.format(remoteip,name,location))
            Indicator.update_tproc_sleep()

        #
        # Part II: Receive replies
        #

        process_replies = True
        while process_replies:
            method_frame, header_frame, body = channel.basic_get(resultq)
            if method_frame:
                data = json.loads(body)
                if '_task' in data:
                    if data['_task'] == 'tproc.reply':
                        try:
                            process_tproc_reply(channel,data)
                            nget += 1
                        except TProcExc as e:
                            log.debug("TProcException: {}".format(e))
                            send_kill(channel, data['_machine'],
                                      "exception: {} for indicator: {}@{}".format(e, data['name'], data['textid']))

                        except Exception as e:
                            log.error("OTHER EXC: {}".format(e))
                            print(data)
                            traceback.print_exc()
                            # raise

                    else:
                        print("Do not know how to process result", data['_task'])
                else:
                    log.info("No _task in data: ", data)
                    pass

                channel.basic_ack(method_frame.delivery_tag)

            else:
                # print('No message returned')
                process_replies = False


        #
        # Part III: Receive hello
        #

        process_helloq = True
        while process_helloq:
            method_frame, header_frame, body = channel.basic_get(helloq)
            if method_frame:
                data = json.loads(body)
                if data['_task'] == 'tproc.hello':
                    try:
                        process_hello(data)
                    except Exception as e:
                        log.error("OTHER EXC: {}".format(e))
                        print(data)
                        traceback.print_exc()
                        # raise

                channel.basic_ack(method_frame.delivery_tag)
            else:
                process_helloq = False


        #
        # Part IV: post-actions
        #
        if time.time() > iupdate_last + iupdate_period:
            try:
                myindicator.update(nget, 'put: {} get: {} in {:.2f}s'.format(nput, nget, time.time() - iupdate_last))
            except okerrupdate.OkerrExc as e:
                log.error('myindicator {} update error: {}'.format(myindicator.name, e))

            iupdate_last = time.time()
            nput = 0
            nget = 0

        time.sleep(args.sleep)

    connection.close()


def main():
    global log
    global channel
    global resultq
    global myindicator
    stop = False

    load_dotenv(dotenv_path='/etc/okerr/okerrupdate')

    def_iname = '{}:mqsender'.format(socket.gethostname())
    def_pem = '/etc/okerr/ssl/client.pem'
    def_capem = '/etc/okerr/ssl/ca.pem'

    parser = argparse.ArgumentParser(description='okerr indicator MQ processor')

    g = parser.add_argument_group('Options')
    g.add_argument('-v', '--verbose', action='store_true', default=False, help='verbose mode')
    g.add_argument('-u', '--unlock', action='store_true', default=False, help='unlock at start')
    g.add_argument('--once', action='store_true', default=False, help='run just once')
    g.add_argument('-s', '--sleep', type=int, default=1, help='sleep time between runs')
    g.add_argument('-i', '--indicator', default=def_iname, help='mqsender keepalive indicator name')

    g = parser.add_argument_group('RabbitMQ options')
    g.add_argument('--rmqhost', default=os.getenv('RMQ_HOST','localhost'), help='RabbitMQ host ($RMQ_HOST, localhost)')
    g.add_argument('--rmqvhost', default=os.getenv('RMQ_VHOST','okerr'),
                   help='RabbitMQ VirtualHost ($RMQ_VHOST, okerr)')
    g.add_argument('--rmquser', default=os.getenv('RMQ_USER', 'okerr'), help='RabbitMQ username (okerr)')
    g.add_argument('--rmqpass', default=os.getenv('RMQ_PASS', 'okerr_default_password'),
                                                  help='RabbitMQ password (okerr_default_password)')
    g.add_argument('--rmqttl', type=int, default=os.getenv('RMQ_TTL','60'), help='TTL (in seconds) for task message')
    g.add_argument('--pem', default=def_pem,
                   help='Client cert+key PEM file: {}'.format(def_pem))
    g.add_argument('--capem', default=def_capem,
                   help='CA cert PEM file: {}'.format(def_capem))



    args = parser.parse_args()

    log = logging.getLogger('mqsender')

    err = logging.StreamHandler(sys.stderr)
    err.setFormatter(logging.Formatter('%(asctime)s %(message)s',
                                       datefmt='%Y/%m/%d %H:%M:%S'))
    err.setLevel(logging.DEBUG)
    log.addHandler(err)

    if args.verbose:
        log.setLevel(logging.DEBUG)
        log.debug('Verbose mode')
    else:
        log.setLevel(logging.INFO)

    op = okerrupdate.OkerrProject()
    myindicator = op.indicator(args.indicator, method='numerical')

    log.debug("Important settings:")
    log.debug("settings.MQ_QUICK_TIME = {}".format(settings.MQ_QUICK_TIME))
    log.debug("settings.MQ_PROCESS_TIME = {}".format(settings.MQ_PROCESS_TIME))
    log.debug("settings.MQ_THROTTLE_TIME = {}".format(settings.MQ_THROTTLE_TIME))

    log.debug('Connect to RMQ host {!r}:5671 vhost: {!r} user: {!r} ca: {!r} client: {!r}'.format(
        args.rmqhost, args.rmqvhost, args.rmquser,
        args.capem, args.pem
    ))

    if args.unlock:
        unlockold()

    while not stop:
        try:
            print("")
            mainloop(args)
        except (pika.exceptions.AMQPError) as e:
            if type(e) == pika.exceptions.AMQPConnectionError:
                print("Connection error: {}".format(str(e)))
            elif(type(e)) == pika.exceptions.ProbableAuthenticationError:
                print("Auth error: {}".format(e))
            else:
                print("Caught exception {}: {}".format(type(e), e))

            time.sleep(10)

main()

