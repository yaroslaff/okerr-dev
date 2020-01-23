#!/usr/bin/env python
# coding=utf-8

from telegram.ext import Updater, CommandHandler, MessageHandler, Filters
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton, ReplyKeyboardMarkup

from telegram.error import (TelegramError, Unauthorized, BadRequest, 
                            TimedOut, ChatMigrated, NetworkError)
import telegram

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


from okerrui.models import Profile, Project
from okerrui.cluster import myci, RemoteServer
from okerrui.impex import Impex
from okerrupdate import OkerrProject, OkerrExc
from myutils import dhms, md_escape

updater = None
stop = False
log = None
commands_cnt = 0


def myname():
    try:
        name = os.environ['HOSTNAME']
    except KeyError:
        name = socket.gethostname()
    return name.split('.')[0]

# my indicators
op = OkerrProject()
hostname = myname()
uptimei = op.indicator("{}:okerrtgbot_uptime".format(hostname))
lastcmdi = op.indicator('{}:okerrtgbot_lastcmd'.format(hostname))

LOOP_TIME = int(getattr(settings, 'TGBOT_LOOP_TIME', 20*60))
        

def is_connection_usable():
    try:
        connection.connection.ping()
    except:
        return False
    else:
        return True

def db_up():
    if not is_connection_usable():
        log.error('pid:{} db connection not usable, close it'.format(os.getpid()))
        connection.close()    


def reg_command(update, ctx):
    bot = ctx.bot
    global commands_cnt
    chat_id = update.message.chat_id
    tgname = update.message.from_user.username
    log.info(u'@{}: {}'.format(tgname, update.message.text))
    lastcmdi.update('OK', details='pid: {} @{}: {}'.format(os.getpid() ,tgname, update.message.text))
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
                return u'Set telegram name {} in profile'.format(tgname)
            else:
                return u'Set telegram name {} in profile'.format(chat_id)
        
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
        log.error('Not found profile for tg user {}. Try little later?'.format(tgname))
        if tgname:
            return u"Telegram user with name '{}' not known in Okerr. Sorry. Please set this name in okerr profile first.".format(tgname)
        else:
            return u"Telegram user with id {} not known in Okerr. Sorry. Please set this id in okerr profile first.".format(chat_id)
        
    except Profile.MultipleObjectsReturned as e:
        log.error('Multiple profiles for tg user {}'.format(tgname))
        return u"More then one telegram user '{}' in Okerr. Use /on <email> command.".format(tgname)




def get_reply_markup(chat_id):
    try:
        if Profile.objects.filter(telegram_chat_id=chat_id).count():
            # linked
            custom_keyboard = [['/off','/help'],['/sum']]
        else:
            custom_keyboard = [['/on','/help']]        

        return ReplyKeyboardMarkup(custom_keyboard, 
            resize_keyboard = True,
            one_time_keyboard = True)
    except Exception as e:
        print(e)
        

def cmd_help(update, ctx):
    bot = ctx.bot
    reg_command(update, ctx)
    chat_id = update.message.chat_id
    try:
        help_text = '''
[/help](/help) - This help
[/on](/on) - Subscribe to alerts
[/sum](/sum) - Quick summary
[/off](/off) - Unsubscribe from alerts
'''            
        bot.send_message(
            chat_id=chat_id, 
            parse_mode = telegram.ParseMode.MARKDOWN,
            reply_markup = get_reply_markup(chat_id),
            text=help_text)
    except Exception as e:
        print(e)

def cmd_start(update, ctx):
    bot = ctx.bot
    args = ctx.args
    reg_command(update, ctx)
    
    bot.send_message(
        chat_id=update.message.chat_id, 
        parse_mode = telegram.ParseMode.MARKDOWN,
        text="Welcome to Okerr telegram bot!")

    cmd_help(bot, update)


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


def cmd_qsum(update, ctx):
    bot = ctx.bot
    args = ctx.args

    reg_command(update, ctx)
    reported = 0
    projects = list()
    
    if len(args):
        textid = args[0]
    else:
        textid = None    

    chat_id = update.message.chat_id

    if textid:
        project = Project.get_by_textid(textid)
        if project is None:
            bot.send_message(
                chat_id=chat_id, 
                text="No such project")
            return
        
        # has access?
        access = False
        for profile in Profile.objects.filter(telegram_chat_id = chat_id):
            if project.member(profile.user):
                access = True
                
        if access:
            projects.append(project)
        else:
            bot.send_message(
                chat_id=chat_id, 
                text="No such project")
            return

    
    else:
        log.info('list all projects for #{}'.format(chat_id))
        try:
            # all available projects
            for profile in Profile.objects.filter(telegram_chat_id = chat_id):
                for p in profile.projects():
                    if not p in projects:
                        projects.append(p)    
        except Exception as e:
            log.error('exc: {}'.format(e))

        log.info("will list {} projects".format(len(projects)))        
    
    if not projects:
        log.info("no projects!")        
        bot.send_message(
            chat_id=chat_id, 
            text="No projects",
            reply_markup = get_reply_markup(chat_id))
        return
    
    for p in projects:
        rs = RemoteServer(ci = p.ci)
        data = rs.api_admin_qsum(p.get_textid())
        log.info("show project {}".format(p.get_textid()))        

        #msg = 'zzzzz'
        tpl = u'''
Project *{}* ({})
Total {} (maintenance: {}, silent: {}, ERR: {})
'''
        if data is None:
            log.error('api_admin_qsum for {} / {} returned None'.format(rs.name, p.get_textid()))
            bot.send_message(
                chat_id=chat_id, 
                parse_mode = telegram.ParseMode.MARKDOWN,
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
                msg += u'[{}]({}) = {} ({}) {} ago\n'.format(
                    md_escape(i['name']), link, i['status'], md_escape(i['details']), i['age'])
            except Exception as e:
                print(e)
            
        if len(data['ERR']) > 5:
            msg += '(Only first 5 of {} shown)\n'.format(len(data['ERR']))
        
        bot.send_message(
            chat_id=chat_id, 
            parse_mode = telegram.ParseMode.MARKDOWN,
            reply_markup = get_reply_markup(chat_id),
            text=msg)
        # end for project
    
        


def cmd_on(update, ctx):
    bot = ctx.bot
    args = ctx.args
    reg_command(update, ctx)
    chat_id=update.message.chat_id 
    
    tgname = update.message.chat.username
    if len(args)>0:
        email = args[0]
    else:
        email = None
    
    log.info(u'set @{} #{} (email: {})'.format(tgname, chat_id, email))            
    msg = set_chat_id( email = email, tgname = tgname, chat_id = update.message.chat_id )
    bot.send_message(
        chat_id=chat_id, 
        # parse_mode = telegram.ParseMode.MARKDOWN,
        reply_markup = get_reply_markup(chat_id),
        text=msg)


def cmd_off(update, ctx):
    bot = ctx.bot
    reg_command(update, ctx)
    tgname = update.message.chat.username
    chat_id = update.message.chat_id    
    
    log.info(u'unset @{} #{}'.format(tgname, chat_id))
    unset_chat_id(chat_id)

    bot.send_message(
        chat_id=update.message.chat_id, 
        text=u"Turned off on all okerr servers.",
        reply_markup = get_reply_markup(chat_id))

def cmd_unknown(update, ctx):
    bot = ctx.bot
    reg_command(update, ctx)
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



def main():
    global updater, log
    

    parser = argparse.ArgumentParser(description='okerr telegram server.')
    parser.add_argument('-v', dest='verbose', action='store_true', 
        default=False, help='verbose mode')


    args = parser.parse_args()  

    assert(settings.TGBOT_TOKEN)

    started = time.time()

    signal.signal(signal.SIGINT, sighandler)    

    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        level=logging.DEBUG)
    log = logging.getLogger('okerr')
    log.info('Okerr TG bot started')

    if args.verbose:
        log.setLevel(logging.DEBUG)
        err = logging.StreamHandler(sys.stderr)
        log.addHandler(err)

    op.setlog(log)
    log.debug('debug')

    updater = Updater(token=settings.TGBOT_TOKEN, use_context=True)
    bot = updater.bot
    dispatcher = updater.dispatcher
    dispatcher.add_error_handler(error_callback)
    
    
    start_handler = CommandHandler('start', cmd_start, pass_args = True)
    help_handler = CommandHandler('help', cmd_help)
    on_handler = CommandHandler('on', cmd_on, pass_args = True)
    qsum_handler = CommandHandler('sum', cmd_qsum, pass_args = True)
    debug_handler = CommandHandler('debug', cmd_debug, pass_args = True)
    off_handler = CommandHandler('off', cmd_off)

    unknown_handler = MessageHandler(Filters.command, cmd_unknown)

    dispatcher.add_handler(start_handler)
    dispatcher.add_handler(help_handler)    
    dispatcher.add_handler(on_handler)    
    dispatcher.add_handler(qsum_handler)    
    dispatcher.add_handler(debug_handler)    
    dispatcher.add_handler(off_handler)
    dispatcher.add_handler(unknown_handler)
    
    print("start polling...")
    updater.start_polling()

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


