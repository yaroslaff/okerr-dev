#!/usr/bin/env python
from django.core.management.base import BaseCommand, CommandError
from okerrui.models import Indicator, Project, ObjectDoesNotExist
from optparse import make_option
from datetime import datetime, timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from myutils import *
#from dateutil.relativedelta import relativedelta
from django.db import connection
import time
import random
import argparse
from multiprocessing import Queue, Process


def prepare(opts):
    created = 0
    processed = 0

    p = Project.get_by_textid(opts['textid'])

    started = time.time()

    for n in range(opts['num']):
        iname = opts['template'].format(n)

        try:
            i = p.get_indicator(iname)
        except ObjectDoesNotExist as e:
            i = Indicator.create(project=p, idname=iname)
            created += 1

        i.status = 'OK'
        i.details = 'prepare...'
        i.save()
        print(i)
        processed += 1

    passed = time.time() - started

    print("Prepared {} indicators (created {}) in {:.2f} seconds ({:.2f} i/sec)".format(
        processed, created, passed,
        processed / passed))


def bench(q, n, opts):
    # print("<{} ({})> started".format(n, os.getpid()))
    # time.sleep(10)
    # print("<{} ({})> stopped".format(n, os.getpid()))

    p = Project.get_by_textid(opts['textid'])

    stats = {'OK': 0, 'n': n}

    processed = 0
    numexc = 0
    stop = False
    started = time.time()
    if opts['shard']:
        startn = opts['num'] * n
        stopn = startn + opts['num']
    else:
        startn = 0
        stopn = opts['num']

    while not stop:
        idx = random.randrange(startn, stopn)
        iname = opts['template'].format(idx)
        i = p.get_indicator(iname)
        i.status = 'OK'
        i.details = 'benchmark (try: {})'.format(processed)
        i.save()
        if not opts['quiet']:
            print("{:02d}: {}".format(n, i))

        processed += 1
        stats['OK'] += 1
        passed = time.time() - started
        # stop?
        if opts['tries']:
            if processed >= args.tries:
                stop = True
        else:
            if passed > opts['seconds']:
                stop = True

    passed = time.time() - started
    stats['passed'] = passed
    stats['processed'] = processed
    q.put(stats)

class Command(BaseCommand):
    help = 'Benchmark operations'

    def add_arguments(self, parser):
        me = "{} {}".format(sys.argv[0], sys.argv[1])
        parser.epilog = 'Example:\n' \
                        '{me} -i bench --num 1000 --prepare\n' \
                        '{me} -i bench --num 100 --processes 10 --shard --seconds 60 --ok'\
            .format(me=me)
        parser.formatter_class = argparse.RawDescriptionHelpFormatter
        ispec = parser.add_argument_group('Indicator specification')
        ispec.add_argument('--textid', '-i', default='bench', help='project TextID')
        ispec.add_argument('--num', type=int, default=1, metavar='NUM', help='num of indicators 1..NUM')
        ispec.add_argument('--processes', type=int, metavar='NUM', default=1, help='num of indicators 1..NUM')
        ispec.add_argument('--shard', action='store_true', default=False,
                           help='Use sharding, each next process will use next NUM indicator index')
        ispec.add_argument('--template', default='bench:{}', help='template for indicator')

        parser.add_argument('--prepare', action='store_true', default=False,
                            help='prepare for test (create indicators)')
        parser.add_argument('--geti', action='store_true', default=False, help='operation: get indicator test')
        parser.add_argument('--iter', type=int, default=100, help='number of iterations')
        parser.add_argument('--ok', action='store_true', default=False, help='operation: update OK test')
        parser.add_argument('--quiet', '-q', action='store_true', default=False,
                            help='quiet mode')
        parser.add_argument('--tries', type=int, default=None, metavar='NUM',
                            help='Stop process --ok after NUM tries')
        parser.add_argument('--seconds', type=int, default=30, metavar='NUM',
                            help='Stop process after NUM seconds')



    def geti_benchmark(self, options):
        random.seed()        
        p = Project.get_by_textid(options['textid'])
        print("Project:", p)
        started = time.time()
        for i in range(1, options['iter']):
            # print "iteration",i
            name = options['template'].format(random.randint(1, options['num']))
            indicator = p.get_indicator(name)
            # print indicator
        stopped = time.time()
        print("{} iterations in {:.2f} seconds ({:.2f} i/sec)".format(i, stopped - started, i / (stopped - started)))
        

    def handle(self, *args, **options):
        if options['geti']:
            print("geti benchmark")
            self.geti_benchmark(options)

        if options['prepare']:
            prepare(options)

        if options['ok']:
            jobs = list()
            q = Queue()
            start = time.time()
            for n in range(options['processes']):
                p = Process(target=bench, args=(q, n, options))
                p.start()
                jobs.append(p)
                # p.join()

            print("wait to stop...")
            for p in jobs:
                p.join()

            passed = time.time() - start
            sum = {
                'OK': 0,
                'processed': 0
            }
            while not q.empty():
                s = q.get()
                if not options['quiet']:
                    print(s)
                for k, v in s.items():
                    if k in sum:
                        sum[k] += v

            sum['passed'] = "{:.3f} sec".format(passed)
            sum['failed'] = sum['processed'] - sum['OK']
            sum['processed_rate'] = "{:.3f} req/sec".format(sum['processed'] / passed)
            sum['OK_rate'] = "{:.3f} req/sec".format(sum['OK'] / passed)

            print("Statistics:\n---")
            for k, v in sum.items():
                print("{}: {}".format(k,v))
            print()
