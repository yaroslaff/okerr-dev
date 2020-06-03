class OkerrError(Exception):
    def __init__(self, msg='', code=None):
        self.msg = msg
        self.code = code

    def __str__(self):
        if self.code:
            return 'ERROR:{} {}'.format(self.code, self.msg)
        else:
            return self.msg

class OkerrProjectNotFound(Exception):
    pass