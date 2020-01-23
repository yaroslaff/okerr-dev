#!/usr/bin/env python

import sys
import redis
import requests
import time
import argparse
import logging

def get_redis():
    return redis.Redis(unix_socket_path='/var/run/redis/redis.sock', decode_responses=True)


def loop(redis):
    while True:
        name = redis.lpop('http_post_list')
        if name:
            log.debug("processing {}".format(name))
            d = redis.hgetall(name)
            url = d['url']
            data = dict(data=d['data'])
            try:
                r = requests.post(url, data = data, timeout=args.timeout)
            except requests.exceptions.RequestException as e:
                log.info("err while report to {}: {}".format(url, e))
            else:
                log.info("reported ({}) to {}".format(r.status_code, url))
            finally:
                redis.delete(name)
        else:
            log.debug("nothing in http_post_list")
            time.sleep(1)

def main():

    global log, args

    parser = argparse.ArgumentParser(description='okerr HTTP POSTer.')
    parser.add_argument('-v', dest='verbose', action='store_true',
        default=False, help='verbose mode')
    parser.add_argument('-t', dest='timeout', type=int, default=3,
        help='timeout in seconds')

    args = parser.parse_args()

    #signal.signal(signal.SIGINT, sighandler)

    logging.basicConfig(
        format='%(asctime)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        level=logging.INFO)

    log = logging.getLogger('okerr')

    if args.verbose:
        log.setLevel(logging.DEBUG)
        log.debug('Verbose mode')
        err = logging.StreamHandler(sys.stderr)
        log.addHandler(err)

    log.info('Okerr HTTP POSTer started')

    r = get_redis()
    loop(r)

main()
