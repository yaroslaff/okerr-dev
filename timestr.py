import shlex
import datetime

from myutils import timesuffix2sec

def validate(v):
    print("Validate:", v, timesuffix2sec(v))
    return True

class TimeStr:
    def __init__(self, s=None, validator = None):
        self.default = None
        self.timeval = list()
        self.validator = validator
        self.loads(s)

    def validate(self, value):
        # either throw ValueError or just pass
        if not self.validator:
            return
        if not self.validator(value):
            raise ValueError('Validator failed {}'.format(value))

    def loads(self, s=None):
        tokens = shlex.split(s)
        self.validate(tokens[0])
        self.default = tokens[0]
        i = iter(tokens[1:])
        for time, value in zip(i,i):
            self.validate(value)
            timea, timeb = time.split('-')
            self.timeval.append(
                (datetime.datetime.strptime(timea, '%H:%M').time(),
                datetime.datetime.strptime(timeb, '%H:%M').time(),
                value)
            )

    def get_value(self, time=None):
        time = time or datetime.datetime.now().time()
        for tuple in self.timeval:
            if time >= tuple[0] and time <= tuple[1]:
                return tuple[2]
        return self.default

if __name__ == '__main__':
    print("main")
    ts = TimeStr('20min 09:00-12:30 20min 12:30-15:00 1h', validator = validate)
    print(ts.get_value())