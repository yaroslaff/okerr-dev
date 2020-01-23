#!/usr/bin/python

import requests
import json
import argparse
import sys

#
# support functions
#

class AuthException(Exception):
    pass

def get_server(textid):
    r = requests.get('https://cp.okerr.com/api/director/'+textid)
    if r.status_code == 200:
        return r.text.rstrip()    

def get_context(user, password, textid, iname=None):
    srv = get_server(textid)
    if iname:
        url = srv + '/pdsjson/'+textid+'/'+iname
    else:
        # just textid
        url = srv + '/pjson/' + textid
    r = requests.get(url, auth=(user,password))
    if r.status_code == 401:
        raise AuthException 
    return json.loads(r.text)
    

parser = argparse.ArgumentParser(description='okerr logic indicator tester')
parser.add_argument('--dump', nargs='+',
                    help='dump project variable')
parser.add_argument('--user', required=True, help='okerr username (email)')
parser.add_argument('--pass', required=True, dest='password', help='okerr password')
parser.add_argument('--id', required=True, help='project textid or indicator iname@textid')
parser.add_argument('--expr', required=True, help='logical expression to test')
args = parser.parse_args()


if '@' in args.id:
    iname, textid = args.id.split('@')
else:
    textid=args.id
    iname=None

#
# get project context
#
try: 
    ctx = get_context(args.user, args.password, textid, iname)
except AuthException:
    print "Wrong login/password"
    sys.exit(1)

#
# override context if you want
# examples:
#
# ctx['hhmm'] = 600 
# ctx['s']['test:la'] = False
# ctx['i']['test:la']['errage'] = 110


if args.dump:
    for var in args.dump:
        print "{} = {}".format(var, json.dumps(eval(var, ctx), indent=4))
        
print eval(args.expr, ctx)        
