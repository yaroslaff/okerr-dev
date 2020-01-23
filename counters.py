import time

class counters():
    def __init__(self):
        self.counters = dict()
        self.cycle_started = time.time()
    
    def add(self, cname, increment = 1):
        if not cname in self.counters:
            self.counters[cname] = 0
        
        self.counters[cname] += increment
        
    def reset(self):
        self.counters = dict()
        self.cycle_started = time.time()

    def age(self):
        return time.time() - self.cycle_started
        
    def dump(self):
        string = ''
        for k in self.counters:
            string += '{}={} '.format(k, self.counters[k])
        return string
        #return str(self.counters)
        
