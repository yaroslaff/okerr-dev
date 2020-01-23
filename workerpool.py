#!/usr/bin/python


from multiprocessing import Pool
import os
import sys
import time
import signal
import json

class WorkerPool():
    
    max_workers = None
    pool = None
    func = None
    tasks = None

    sumitted = None
    
    def __init__(self,func,n=20, maxtasksperchild=5):
        self.func = func
        self.max_workers = n
        self.tasks = list()
        self.pool = Pool(processes = self.max_workers, maxtasksperchild = maxtasksperchild)
        self.submitted = dict()
        self.created = time.time()
        
    def age(self):
        return time.time() - self.created

    def add(self,task):
        res = self.pool.apply_async(self.func, task)
        # print "wp task: {}".format(task)
    
        self.submitted[id(res)] = { 'iname': str(task), 'submitted': int(time.time()) }
    
        self.tasks.append(res)
    
    
    def nready(self):
        nready = 0
        for t in self.tasks:
            if t.ready():
                nready+=1
        return nready
    
    def dump(self):
        nready = self.nready()
        print("tasks: {}/{} ready".format(nready, len(self.tasks)))
        for t in self.tasks:
            s = self.submitted[id(t)]
            print(".. {} ({} ago)".format(s['iname'], int(time.time() - s['submitted'])))

    def size(self):
        return len(self.tasks)

    def close(self):
        print("close started...")
        self.pool.close()            
        #self.pool.join()
        self.pool.terminate()
        print("closed")
    
    
    def results(self):
        out = list()
        ready = [ t for t in self.tasks if t.ready() ]
        notready = [ t for t in self.tasks if not t in ready ]

        self.tasks = notready
        for r in ready:
            del self.submitted[id(r)]            
            result = r.get()
            out.append(result)
        return out 
    

if __name__ == '__main__':        


    class task():
        time = None
        def __init__(self, n,time=None):
            self.n = n
            if time is None:
                self.time = n
            else:
                self.time = time
        
        def __repr__(self):
            return "task {} ({} sec)".format(self.n, self.time)


    def myfunc(a):
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        time.sleep(a.time)
        return a.n*a.n
        

    def sighandler(signum, frame):
        global stop
        print("caught signal",signum)
        stop = True

    stop = False
    
    signal.signal(signal.SIGINT, sighandler)
    
    wp = worker_pool(myfunc)
    for i in xrange(1000):        
        wp.add(task(i))

    while True:
        wp.dump()
        print("size:", wp.size())
        for r in wp.getlist():
            print("R:",r)
        time.sleep(5)
        if stop:
            print("stopping!")
            wp.close()    
            sys.exit(0)


