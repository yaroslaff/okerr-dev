import myutils
import datetime

# default variables
HOSTNAME = 'localhost'
CLUSTER_NAME = 'LOCAL'
MACHINES = {
    0: {
        'ci': 0,
        'name': HOSTNAME,
        'url': 'http://localhost.okerr.com/',
        'netprocess': True
    }
}

DB_HOST = "localhost"
SITEURL = None
SECRET_KEY = '<default secret key, will be overwritten by environment or config>'
TRUSTED_IPS = []
TRUSTED_HOSTS = []
TRUSTED_NETS = []
LOG_SYSLOG = True
LOG_STDOUT = False
HONOR_LAST_FAIL = True
LOG_SERVER = None
MYIP = None
SERVER_EMAIL = 'noreply@okerr.com'
OKERR_REDIS_DB = 1
TPROC_MAXSLEEP = 30
JKEYS_TPL = "{}"
OAUTH2_ADV_LIST = list()

ENABLE_PRELOGIN = False
ENABLE_MOTD = False

# MAIL settings
EMAIL_HOST = 'localhost'
EMAIL_PORT = 25
FROM = '"okerr robot" <noreply@okerr.com>'
TGBOT_TOKEN = None
MAIL_RECIPIENTS = ['*']
MYMAIL_METHOD = 'smtp'
MYMAIL_FOOTER = ''  # Not None! 'elasticemail' or any other string
LOGMAIL = []  # list of emails to send log messages

IMPORT_PATH = 'demo' # from settings.BASE_DIR

PROCSLEEP = 10

TPROC_GET_MAX = 100

# cleaning old data
LOGRECORD_AGE = datetime.timedelta(days=31)
LOGRECORD_UPDATE_AGE = datetime.timedelta(days=3)
ICHANGE_AGE = datetime.timedelta(days=31)

# MQ time settings
MQ_QUICK_TIME = 10 # which indicators are processed as 'quick' (loop-processed on sensor by default)
MQ_PROCESS_TIME = 30 # what delay we allow for network processing and queue (scheduled = expected+MQ_PROCESS_TIME). Also, this allows
MQ_THROTTLE_TIME = 300 # how often mq netprocess should report quick indicator
MQ_RETRY_TIME = 60 # if code not 200

assert(MQ_THROTTLE_TIME >= MQ_QUICK_TIME)


# cluster sync parameters
SYNC_MAP = {
    HOSTNAME: []
}
