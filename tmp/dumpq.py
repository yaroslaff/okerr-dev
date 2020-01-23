#!/usr/bin/env python
import os, sys
import logging, logging.handlers
import argparse
import pika
import ssl

resultq = None
redis_conn = None

def main():
    global log
    global channel
    global resultq
    global redis_conn

    def_pem = '/etc/okerr/ssl/client.pem'
    def_capem = '/etc/okerr/ssl/ca.pem'

    parser = argparse.ArgumentParser(description='okerr indicator MQ processor')

    g = parser.add_argument_group('Options')
    g.add_argument('-n', metavar='NUM', type=int, default=None, help='number of messages')
    g.add_argument('-q', '--queue', metavar='QUEUE', default=None, help='queue name')

    g = parser.add_argument_group('RabbitMQ options')
    g.add_argument('--rmqhost', default=os.getenv('RMQ_HOST','localhost'), help='RabbitMQ host ($RMQ_HOST, localhost)')
    g.add_argument('--rmqvhost', default=os.getenv('RMQ_VHOST','okerr'), help='RabbitMQ VirtualHost ($RMQ_VHOST, okerr)')
    g.add_argument('--rmquser', default=os.getenv('RMQ_USER', 'okerr'), help='RabbitMQ username (okerr)')
    g.add_argument('--rmqpass', default=os.getenv('RMQ_PASS', 'okerr_default_password'),
                   help='RabbitMQ password (okerr)')
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

    log.setLevel(logging.DEBUG)

    log.debug('Connect to RMQ host {!r}:5671 vhost: {!r} user: {!r} ca: {!r} client: {!r}'.format(
        args.rmqhost, args.rmqvhost, args.rmquser,
        args.capem, args.pem
    ))

    credentials = pika.PlainCredentials(args.rmquser, args.rmqpass)
    context = ssl.create_default_context(cafile=args.capem)
    context.load_cert_chain(args.pem)
    ssl_options = pika.SSLOptions(context, "rabbitmq")

    connection = pika.BlockingConnection(
        pika.ConnectionParameters(
            host=args.rmqhost, port=5671,
            virtual_host=args.rmqvhost,
            ssl_options=ssl_options,
            credentials=credentials))
    channel = connection.channel()

    channel.queue_declare(queue=args.queue)

    while True:

        #
        # Part II: Receive replies
        #

        stop = False
        n=0
        while not stop:
            method_frame, header_frame, body = channel.basic_get(args.queue)
            if method_frame:
                print(body)
                n += 1
                if n == args.n:
                    stop = True
            else:
                stop = True

    connection.close()

main()

