#!/usr/bin/env python
# coding=utf-8

# from telegram.ext import Updater, CommandHandler, MessageHandler, Filters
# from telegram import InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton, ReplyKeyboardMarkup

# from telegram.error import (TelegramError, Unauthorized, BadRequest,
#                            TimedOut, ChatMigrated, NetworkError)
# import telegram

import telebot

import argparse
import logging
import json
import time
import signal
import sys, os
import socket

import django
#from django.core.urlresolvers import reverse
from django.urls import reverse
from django.conf import settings
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "okerr.settings")
django.setup()
from django.db import connection

from requests.exceptions import RequestException

from okerrui.models import Profile, Project
from okerrui.cluster import myci, RemoteServer
from okerrui.impex import Impex
from okerrupdate import OkerrProject, OkerrExc
from myutils import dhms, md_escape

bot = telebot.TeleBot(settings.TGBOT_TOKEN)
started = time.time()

# updater = None
stop = False
log = None
commands_cnt = 0

main_rs = None


def msgargs(message):
    return message.text.split(' ')[1:]

def myname():
    try:
        name = os.environ['HOSTNAME']
    except KeyError:
        name = socket.gethostname()
    return name.split('.')[0]

# my indicators
op = OkerrProject()
hostname = myname()
uptimei = op.indicator("{}:telebot_uptime".format(hostname))
lastcmdi = op.indicator('{}:telebot_lastcmd'.format(hostname))

LOOP_TIME = int(getattr(settings, 'TGBOT_LOOP_TIME', 20*60))
        

def is_connection_usable():
    try:
        connection.connection.ping()
    except Exception as e:
        log.info("db connection check exception: {} {}".format(type(e), e))
        return False
    else:
        return True

def db_up():
    return
    if not is_connection_usable():
        log.info('pid:{} db connection not usable, close it'.format(os.getpid()))
        connection.close()    


def reg_command(message):
    global commands_cnt
    tgname = message.from_user.username
    log.info('@{}: {}'.format(tgname, message.text))
    lastcmdi.update('OK', details='pid: {} @{}: {}'.format(os.getpid() ,tgname, message.text))
    commands_cnt += 1
    db_up()
    
def sighandler(signum, frame):
    global stop
    print("caught signal {}".format(signum))
    stop = True

def unset_chat_id(chat_id):
    try:
        for rs in RemoteServer.all_rs():
            rs.api_admin_tglink(chat_id = chat_id)
    except Exception as e:
        print(e)

def set_chat_id(email, tgname, chat_id):            
    
    try:
        # print "set chat id email: {} tgname: {} chat_id: {}".format(email, tgname, chat_id)    
        # find profile
        if email:
            # do not use tgname in this search!
            profile = Profile.objects.get(user__email=email)
        else:
            if tgname:
                profile = Profile.objects.get(telegram_name = tgname)
            else:
                profile = Profile.objects.get(telegram_name = str(chat_id))
                    
        # verify profile
        if profile.telegram_name != tgname and profile.telegram_name != str(chat_id):
            if tgname:
                return 'Set telegram name {} in profile'.format(tgname)
            else:
                return 'Set telegram name {} in profile'.format(chat_id)
        
        rs = RemoteServer(ci = profile.ci)
        if tgname:
            jr = rs.api_admin_tglink(email, tgname, chat_id)
        else:
            jr = rs.api_admin_tglink(email, chat_id, chat_id)
                
        r = json.loads(jr)
        
        # sync if needed
        if rs.ci != myci():
            for username in r['sync']:
                data = rs.get_user(email)
                ie = Impex()           
                ie.set_verbosity(0)
                ie.preimport_cleanup(data)
                ie.import_data(data)

        return r['msg']
            
    except Profile.DoesNotExist as e:
        log.info('Not found profile for tg user {}. Try little later?'.format(tgname))
        if tgname:
            return "Telegram user with name '{}' not known in Okerr. Sorry. Please set this name in okerr profile first and try little later.".format(tgname)
        else:
            return "Telegram user with id {} not known in Okerr. Sorry. Please set this id in okerr profile first and try little later.".format(chat_id)
        
    except Profile.MultipleObjectsReturned as e:
        log.error('Multiple profiles for tg user {}'.format(tgname))
        return "More then one telegram user '{}' in Okerr. Use /on <email> command.".format(tgname)


def get_reply_markup(chat_id):

    try:
        markup = telebot.types.ReplyKeyboardMarkup()

        if main_rs.api_admin_chat_id(chat_id):
            markup.row(
                telebot.types.KeyboardButton('/off'),
                telebot.types.KeyboardButton('/help')
            )
            markup.row(
                telebot.types.KeyboardButton('/sum'),
                telebot.types.KeyboardButton('/recheck')
            )
        else:
            markup.row(
                telebot.types.KeyboardButton('/on'),
                telebot.types.KeyboardButton('/help')
            )
        return markup
    except Exception as e:
        print(e)
        
@bot.message_handler(commands=['help'])
def cmd_help(message):
    reg_command(message)
    chat_id = message.chat.id
    try:
        help_text = '''
[/help](/help) - This help
[/on](/on) - Subscribe to alerts
[/sum](/sum) - Quick summary
[/off](/off) - Unsubscribe from alerts
'''            
        bot.send_message(
            chat_id=chat_id, 
            parse_mode = "Markdown",
            reply_markup = get_reply_markup(chat_id),
            text=help_text)
    except Exception as e:
        print("EXCEPTION: {} {}".format(type(e), e))


def cmd_debug(update, ctx):
    bot = ctx.bot
    args = ctx.args

    reg_command(update, ctx)

    chat_id = update.message.chat_id
    tgname = update.message.from_user.username

    log.info('debug @{} #{}'.format(tgname, chat_id))

    bot.send_message(
        chat_id=update.message.chat_id, 
        text="You are @{}, chat_id: {}".format(tgname, chat_id))
    
    for p in Profile.objects.filter(telegram_name = tgname):
        bot.send_message(
            chat_id=update.message.chat_id, 
            text="Profile {} @{}, chat_id: {} ci: {}/{}".format(p.user.username, p.telegram_name, p.telegram_chat_id, p.ci, myci()))


@bot.message_handler(commands=['recheck'])
def cmd_recheck(message):
    reg_command(message)
    projects = list()

    chat_id = message.chat.id

    username = main_rs.api_admin_chat_id(chat_id)
    if username is None:
        tgname = message.from_user.username
        error_msg = "chat id: {} tg name: {} not linked to any account".format(chat_id, tgname)
        log.info(error_msg)
        bot.send_message(
            chat_id=chat_id,
            text=error_msg,
            reply_markup=get_reply_markup(chat_id))
        return

    project_list = main_rs.api_admin_member(username)
    if project_list is None:
        log.info('Failed to get project list for user {} from {}'.format(username, main_rs))
        bot.send_message(
            chat_id=chat_id,
            text="Internal exception, please contact support",
            reply_markup=get_reply_markup(chat_id))
        return

    for textid in project_list:
        projects.append(textid)

    if not projects:
        log.info("no projects!")
        bot.send_message(
            chat_id=chat_id,
            text="No projects",
            reply_markup=get_reply_markup(chat_id))
        return

    for textid in projects:
        url = main_rs.api_director(textid)
        rs = RemoteServer(url=url)

        l = rs.api_recheck(textid)

        if l is None:
            log.error('api_recheck for {} / {} returned None'.format(rs.name, p.get_textid()))
            bot.send_message(
                chat_id=chat_id,
                parse_mode="Markdown",
                reply_markup=get_reply_markup(chat_id),
                text='Server {} for project {} unavailable at moment. Sorry. Try again later.'.format(rs.name,
                                                                                                      p.get_textid()))
            return


        log.info("rechecked project {}: {} indicators".format(textid, len(l)))

        if l:
            # not empty list
            msg = "Project {}: recheck: {}".format(textid, ' '.join(l[:5]))
        else:
            msg = "Project {}: nothing to recheck".format(textid)

        bot.send_message(
            chat_id=chat_id,
            parse_mode="Markdown",
            reply_markup=get_reply_markup(chat_id),
            text=msg)
        # end for project


@bot.message_handler(commands=['sum'])
def cmd_qsum(message):

    reg_command(message)
    reported = 0
    projects = list()

    chat_id = message.chat.id

    username = main_rs.api_admin_chat_id(chat_id)
    if username is None:
        tgname = message.from_user.username
        error_msg = "chat id: {} tg name: {} not linked to any account".format(chat_id, tgname)
        log.info(error_msg)
        bot.send_message(
            chat_id=chat_id,
            text=error_msg,
            reply_markup = get_reply_markup(chat_id))
        return

    project_list = main_rs.api_admin_member(username)
    if project_list is None:
        log.info('Failed to get project list for user {} from {}'.format(username, main_rs))
        bot.send_message(
            chat_id=chat_id,
            text="Internal exception, please contact support",
            reply_markup = get_reply_markup(chat_id))
        return


    for textid in project_list:
        projects.append(textid)

    if not projects:
        log.info("no projects!")        
        bot.send_message(
            chat_id=chat_id, 
            text="No projects",
            reply_markup = get_reply_markup(chat_id))
        return
    
    for textid in projects:
        url = main_rs.api_director(textid)
        rs = RemoteServer(url = url)
        data = rs.api_admin_qsum(textid)
        log.info("show project {}".format(textid))

        #msg = 'zzzzz'
        tpl = '''
Project *{}* ({})
Total {} (maintenance: {}, silent: {}, ERR: {})
'''
        if data is None:
            log.error('api_admin_qsum for {} / {} returned None'.format(rs.name, p.get_textid()))
            bot.send_message(
                chat_id=chat_id, 
                parse_mode = "Markdown",
                reply_markup = get_reply_markup(chat_id),
                text='Server {} for project {} unavailable at moment. Sorry. Try again later.'.format(rs.name, p.get_textid()))
            return
        
        msg = tpl.format(data['project'], data['textid'],
            data['cnt']['total'],
            data['cnt']['maintenance'],
            data['cnt']['silent'],
            data['cnt']['ERR'])
                
        for i in data['ERR'][:5]:
            try:
                link = rs.reverse('okerr:ilocator', {'pid': data['textid'], 'iid': i['name']})                
                msg += '[{}]({}) = {} ({}) {} ago\n'.format(
                    md_escape(i['name']), link, i['status'], md_escape(i['details']), i['age'])
            except Exception as e:
                print(e)
            
        if len(data['ERR']) > 5:
            msg += '(Only first 5 of {} shown)\n'.format(len(data['ERR']))

        bot.send_message(
            chat_id=chat_id, 
            parse_mode = "Markdown",
            reply_markup = get_reply_markup(chat_id),
            text=msg)
        # end for project


@bot.message_handler(commands=['info'])
def cmd_info(message):
    reg_command(message)
    chat_id=message.chat.id
    tgname = message.from_user.username

    uptime = time.time() - started
    hostname = socket.gethostname()

    msg = 'Hello {}!\nYour chat id is {}\nHostname: {}\nUptime: {}'.format(tgname, chat_id, hostname, dhms(uptime))

    bot.send_message(
        chat_id=chat_id,
        # parse_mode = telegram.ParseMode.MARKDOWN,
        reply_markup = get_reply_markup(chat_id),
        text=msg)

@bot.message_handler(commands=['on'])
def cmd_on(message):
    reg_command(message)
    chat_id=message.chat.id
    tgname = message.from_user.username

    args = msgargs(message)
    try:
        email = args[0]
    except IndexError:
        email = None
    
    log.info('set @{} #{} (email: {})'.format(tgname, chat_id, email))
    msg = set_chat_id( email = email, tgname = tgname, chat_id = chat_id )
    bot.send_message(
        chat_id=chat_id, 
        # parse_mode = telegram.ParseMode.MARKDOWN,
        reply_markup = get_reply_markup(chat_id),
        text=msg)

@bot.message_handler(commands=['off'])
def cmd_off(message):
    reg_command(message)
    chat_id=message.chat.id
    tgname = message.from_user.username

    log.info('unset @{} #{}'.format(tgname, chat_id))
    unset_chat_id(chat_id)

    bot.send_message(
        chat_id=chat_id,
        text="Turned off on all okerr servers.",
        reply_markup = get_reply_markup(chat_id))

def cmd_unknown(update):
    reg_command(update)
    bot.send_message(
        chat_id=update.message.chat_id, 
        text="Sorry, I didn't understand that command.")


def error_callback(update, ctx):
    bot = ctx.bot
    log.error("tgbot {}: {}".format(ctx.error.__class__.__name__, ctx.error))
    try:
        pass
        # raise ctx.error
    except Unauthorized:
        # remove update.message.chat_id from conversation list
        pass
    except BadRequest:
        # handle malformed requests - read more below!
        pass
    except TimedOut:
        # handle slow connection problems
        pass
    except NetworkError:
        # handle other connection problems
        pass
    except ChatMigrated as e:
        # the chat_id of a group has changed, use e.new_chat_id instead
        pass
    except TelegramError:
        # handle all other telegram related errors
        pass


@bot.message_handler(commands=['start'])
def cmd_start(message):
    reg_command(message)

    bot.reply_to(
        message,
        # parse_mode = telegram.ParseMode.MARKDOWN,
        "Welcome to Okerr telegram bot!")
    cmd_help(message)

def main():
    #global updater, log
    global log
    global bot
    global main_rs

    parser = argparse.ArgumentParser(description='okerr telegram server.')
    parser.add_argument('-s', '--server',
        default=settings.SERVER_URL, help='Remote okerr server URL')
    parser.add_argument('-v', dest='verbose', action='store_true',
        default=False, help='verbose mode')


    args = parser.parse_args()  

    assert(settings.TGBOT_TOKEN)

    main_rs = RemoteServer(url=args.server)
    assert(main_rs)

    signal.signal(signal.SIGINT, sighandler)    

    #logging.basicConfig(
    #    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    #    level=logging.DEBUG)

    log = logging.getLogger('okerr-telebot')
    out = logging.StreamHandler(sys.stdout)
    out.setFormatter(logging.Formatter('%(asctime)s %(message)s',
                                       datefmt='%Y/%m/%d %H:%M:%S'))
    log.addHandler(out)

    err = logging.StreamHandler(sys.stderr)
    err.setLevel(logging.ERROR)
    log.addHandler(err)

    if args.verbose:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    log.propagate = False
    op.setlog(log)

    print("start polling...")
    # updater.start_polling()
    try:
        bot.polling(none_stop=True)
    except RequestException as e:
        log.error('Caught request exceptions {}: {}'.format(type(e), e))
        sys.exit(1)

    print("stop polling")

    while not stop:
        # db_up()
        uptime = time.time() - started
        try:
            uptimei.update('OK', 'pid: {} Uptime: {} cmds: {}'.format(os.getpid(), dhms(uptime), commands_cnt))
        except OkerrExc as e:
            log.error("update error: {}".format(str(e)))
        log.info('tick-tock')
        time.sleep(LOOP_TIME)
    
    print("stopping bot.. please wait a little")
    stop_time = time.time()
    updater.stop()    
    print("stopped after {}s".format(int(time.time() - stop_time)))
    print("Bye.")


main()
