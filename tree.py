import json
import copy
import string

#
# key and dirname can have '@' 
# key name cannot have ':'
# key value can have : and/or @ 
#
#



class TreeKey(object):
    name = None
    fullname = None # fullname is path+sepchar+name
    path = None
    value = None # None for subdir, '' or value for string
    tree = None


    # return name as int if possible, or as string
    def intname(self):
        try:
            return int(self.name)
        except ValueError as e:
            return self.name

    # generator. returns all children of this treekey
    def children(self):
        return self.tree.treekeys(self.fullname)

    def nchildren(self):
        return self.tree.nchildren(self.fullname)        

    def __repr__(self):
        return "'"+self.name+"'"

    def link(self):
        try:
            if self.name.startswith('@include'):
                return self.name.split(' ',1)[1]
            else:
                return None
        except IndexError:
            return None

    def isdir(self):
        if self.value is None or isinstance(self.value,dict):
            # bad approach! dir can start with @, e.g. @access
            #if self.name.startswith('@'): 
                # special @ directive, not a subdir
            #    return False
            # no value and not directive, so this is DIR
            return True
        else:
            # has value => this is not a DIR
            return False


class Tree(object):
    
    # d = dict()
    
    sepchar=':' # if override, this will break smartsplit()
     
    def __init__(self):
        self.d = dict()

    #
    # remove @anything keys from any dict
    #
    def noat(self,curd=None):
        if curd is None:
            curd = self.d
            
        newd = {}
        if isinstance(curd,str):
            return curd
        
        if isinstance(curd,dict):
            for k in curd:
                if not k.startswith('@'):                    
                    newd[k]=curd[k]
                else:
                    pass
        return newd        

    @staticmethod
    #
    # keyname must have allowed : for includes
    # to allow to '@include ...' keys
    # because two '@include' keys share same name and overwrite each other
    #
    # space allowed in string key (not dirname) for '@include[space]path'
    #
    # * is required for @include conf:web:*
    # . is very needed for hostnames as dirnames, e.g. domain.com
    #
    # ' ', '*' and ':' IS NOT RECOMMENDED
    #
    
    def keyname_valid(key,value=None):
        #key_re="^[@a-zA-Z\-\_]*$"
        valid = string.ascii_letters + string.digits + '-_@:.'
        if isinstance(value,str) and key.startswith('@'):
            # this is dir
            valid += ' *'
            # check if this is valid directive
            if key.startswith('@include '):
                if len(key) == len('@include '):
                    return False
            else:
                # starts with @ but not known directive
                return False
                            
        #print "valid: '{}' key: '{}' val: '{}'".format(valid,key,value)
        return all(x in valid for x in key)


    #
    # returns dict with processed arrays
    #
    # uses self.d for includes
    #
    def doinclude(self, curd=None, depth=10):
        if curd is None:
            curd = self.d
        
        newd = {}
        
        if isinstance(curd,str):
            return curd
        
        for k in curd:
            
            if isinstance(curd[k],dict):
                # print "Dive into", k
                newd[k]=self.doinclude(curd[k],depth-1 if depth else 0)
            else:
                # string
                if k.startswith('@include') and depth:
                    #print "process include ",k
                    (inc, ipath) = k.split(' ')
                    # ipath = curd[k]
                    ipatha = ipath.split(self.sepchar)
                    # print "!! include",ipatha
                    if ipatha[-1]=='*':
                        # print "asterisk include"
                        rawd = self.godeep(ipatha[:-1]).copy()
                        # print "rawd:",rawd
                        if isinstance(rawd,dict):
                            rawd = self.doinclude(rawd,depth-1 if depth else 0)
                            # must be dict for asterisk include!
                            # newd = rawd.update(newd)
                            for k in rawd:
                                if not k in newd:
                                    newd[k]=rawd[k]
                    else:
                        try:
                            #print "usual include",ipatha
                            rawd = self.godeep(ipatha)
                            #print "godeep ok"
                            rawd = self.doinclude(rawd,depth-1 if depth else 0)
                            #print "doinclude ok"
                            # print "rawd:",rawd
                            newd[ipatha[-1]] = rawd
                        except KeyError:
                            # print "cannot include",ipatha, k
                            pass
                # simple string, not include     
                else:
                    newd[k]=curd[k]
        return newd        
        
    #
    # return subtree with path
    #
    
    def key(self, path, noat=True,include=True):

        #!!!
        if include:
            d = self.doinclude(copy.deepcopy(self.d))
        else:
            d = copy.deepcopy(self.d)
        
        d = self.godeep(path,d)
        if noat:
            d = self.noat(d)
        else:
            pass
        return d

    #
    # key and path is either ':' separated strings or lists
    # looks for path+key
    # if not found, removes last element from path and repeats
    #
    # return None if not found at all 
    #

    def fallback(self,path,key):
        #print "fallback path:{}, key:'{}'".format(path,key)
        if isinstance(path,str):
            patha = path.split(self.sepchar)
            patha = filter(None,patha)
        else:
            patha = list(path)
            
                        
        if isinstance(key, str):
            keya = key.split(self.sepchar)
        else:
            keya = list(key)    

                
        if len(patha) == 0:
            try:
                val = self.key(key)
                return val
            except KeyError as e:
                print("key error", str(e))
                return None
        else:
            while True:
                trypath = patha + keya
                try:
                    val = self.key(trypath)
                    return val
                except KeyError:
                    if len(patha):
                        patha.pop()
                    else:
                        return None        
        print("unreachable code?")
        return None
 
 
    #
    # returns part of d (=self.d) by path
    #
    # path is either ':'-string, or list 
    #
    # can raise KeyError
    #
            
    def godeep(self,path=None,d=None):
        if d is None:
            d=self.d
        if isinstance(path,str):
            #print "str, split"
            patha = path.split(self.sepchar)
            #print "patha: ",patha
        elif isinstance(path,list):
            patha=path
        elif isinstance(path,type(None)):
            patha=[]
        
        patha = filter(None,patha)
                  
        dd=d   
        for r in patha:
            if isinstance(dd,str):
                # cannot dive into string
                raise KeyError
            #print "dd: ",dd
            #print "dive",r
            
            dd=dd[r]
        return dd
      
        #if len(patha) == 0:
        #    return d
        
        #print "godeep path '{}' '{}'".format(path,patha[0])
        #return self.godeep(patha[1:],d[patha[0]])
        
            
            
    #
    # add name to path with value
    #
    # if name is None and value dict, add each key from dict
    #

    def add(self, path, name, value=None):
    
        # print("tree add path={} name={} value={}".format(path,name,value))
        #print "d:",self.d
        
        
        #
        # check if keyname is valid.
        # Note: None is valid (initialization), if value is dict
        #
        if not (name is None and isinstance(value,dict) or Tree.keyname_valid(name,value)):
            print("not valid name '{}'".format(name))
            raise ValueError
            return None
    
        if path is None:
            path=''
            
        if value is None:
            value=dict()
        else:
            value = copy.deepcopy(value)
                            
        # print("add '{}' to path '{}'".format(name,path))
        dd = self.godeep(path,self.d)
        #print "got dd:",dd
        
        if name is None and isinstance(value, dict):
            for k in value:
                dd[k]=value[k]
        else:        
            dd[name]=value  

        #print "d (after):",self.d


    #
    # smartsplit
    #
    # better then split, because aware of keys which starts with '@' and contains ':'
    #

    @staticmethod
    def smartsplit(s):
        if '@' in s:
            # print "tricky: ",s
            if s.startswith('@'):
                # no path, starts with key
                path = [s]
            else:
                [p,k] = s.split(':@')
                print("p:",p,"k:",k)
                path = p.split(':')
                path.append('@'+k)
        else:
            # print "simple: ",s
            path = s.split(':')
        return path
    
    #
    # delete
    #
    # !!! TODO check mkdir from UI
    # check delete from UI, keys/dir, special, usual
    #
    def delete(self,path,d=None):
    
    
        if d is None:
            d=self.d
        if isinstance(path,str) or isinstance(path,unicode):
            #patha = Tree.smartsplit(path)
            patha = path.split(':')            
        elif isinstance(path,list):
            patha=path
        
        
        patha = filter(None,patha)

        if len(patha)==0:
            # no path given
            return
        
          
        dd=d   
        for r in patha[:-1]:
            if isinstance(dd,str):
                # cannot dive into string
                raise KeyError        
            dd=dd[r]
        
        if patha[-1] == '*':
            # delete all keys from dd
            for k in list(dd):
                del dd[k]            
        else:
            # delete one key    
            del dd[patha[-1]]
    
    
    def getjson(self):
        return json.dumps(self.d)
        
    def loadjson(self,jsonkeys):
        d = json.loads(jsonkeys)
        self.add('',name=None,value=d)

    # tree.getkey
    #
    # wrapper. fallback if fallback
    # key if no fallback
    #
    def getkey(self,path,fallback=True):
        
        
        fullpath = path.split(':')
        keyname=fullpath.pop()
        
                
        if fallback:
            x = self.fallback(fullpath,keyname)
            return x
        else:
            # no fallback, just key
            k = self.key(path)            
            return k
            
    #
    # prints self.d with pretty json
    #        
    def dump(self,path=None):
        if path is None:
            d=self.d
        else:
            d=self.key(path)
        print(json.dumps(d, indent=4, separators=(',', ': ')))

    # nchildren
    # return number of children. always 0 for non-dirs
    def nchildren(self,path=None):
        d = self.godeep(path)

        if type(d) != dict:
            return 0
            
        n=0
        for k in d.keys():
            n+=1
        return n

    #
    # gives resolved path to 
    #
    def resolve(self,origpath,dd=None):
        if dd is None:
            dd = self.d
        
        newpath=list()
            
        if isinstance(origpath,str) or isinstance(origpath,unicode):
            #print "str, split"
            origpatha = origpath.split(self.sepchar)
   
        for pelem in origpatha:
            # print "go deep {}".format(pelem)
            includes = dict()
            for dde in dd:
                if not dde.startswith('@include '):
                    continue
                incpath = dde.split(' ')[1]
                incname = incpath.split(':')[-1]
                includes[incname]=incpath                                            
            
            if pelem in dd:
                dd = dd[pelem]
                newpath.append(pelem)
            else:
                # print "no key {}! maybe include?".format(pelem)
                if pelem in includes:                    
                    newpath = includes[pelem].split(':')
                    dd = self.godeep(newpath)
                else:
                    # print "NO SUCH KEY"
                    return None
        return ':'.join(newpath)




    # treekeys
    # iterate over keys 
    def treekeys(self,path=None):
      d = self.godeep(path)
      for k,v in d.items():
        #print "WALK k:{} v:{}".format(k,v)
        tk = TreeKey()
        tk.name = k
        tk.tree = self
        if path:
            tk.path=path
            tk.fullname=path+self.sepchar+k
        else:
            tk.path=''
            tk.fullname=k            
        if isinstance(v,str) or isinstance(v,unicode):
            tk.value = v
        yield tk
    
        
 
    def rootkey(self):
        tk = TreeKey()
        tk.name = ''
        tk.tree = self
        tk.path=''
        tk.fullname=''
        return tk

      
if __name__ == '__main__':
    s = {'person1': {'name': 'Jack','age': 30}, 'person2': {'name': 'John'}}            
    t = Tree()
    data = {
        'title': 'asdf asdf asdf',
        'num' : '123',
        'servers': {
            'farm1': {
                'clusterA': {
                    'server1': {
                            '@include checks:ch3:*': ''
                        }
                }
            },
            '@access': {
                'user':'pass'
            }
        },
        'checks': {
            'ch1': {
                'method': 'heartbeat'
            },
            'ch2': {
                'method': 'OK'
            },
            'ch3': {
                '@include checks:ch1': '',
                '@include checks:ch2': ''
            }
        }
    }


    jkeys = '''{"@access": {"client": "c3t442xQWI"}, "conf": {"webserver": {"aaa": "bbb"}}, "lib": {"biglog": {"checkmethod": "streqd", "name": "{iname}:biglog", "sequence": {"1": {"path": "/var/log", "command": "DIR"}, "3": {"field": "size", "command": "SORT"}, "2": {"command": "FILTER", "argline": "type=='REG'"}, "5": "TOP 10", "4": "REV", "6": "FORMAT {path} {size}"}}, "tcpports": {"checkmethod": "streqd", "name": "{iname}:opentcp", "sequence": {"10": "CONNECTIONS", "30": "SORT field=port", "20": "FILTER status=='LISTEN' and proto=='tcp' and basename != 'smtpd'", "40": "FORMAT {proto}:{port} {basename}"}}}, "servers": {"server1": {"@include conf:webserver": "", "aaa": "bbb"}}}'''

    farm2 = {
        'farm2': {
            'server1': {
                'k': 'v'
            }
        }
    }

    #t.add('','aaa','bbb')
    #t.add('',name=None,value=data)
    t.loadjson(jkeys)
    #t.add('servers',name=None,value=farm2)
    #t.dump()    
    #print "SUB:SS:",t.godeep('sub:ss:sss1')
    #print t.key('servers:farm1:clusterA:server1:key')
    #print t.fallback('servers','@access')        
    #print "INCLUDES"
    #t.delete('title')
    #t.delete('servers:farm1')

    #t.delete('conf:webserver')

    t.add('servers:server1','@access',None)

    def printtree(tk,prefix=""):
        if tk.isdir():
            print(prefix+"[+] {}".format(tk.fullname))
            for tki in tk.children():
                printtree(tki,prefix+"  ")
        else:
            print(prefix+"E:",tk.name,"=",tk.value)
    printtree(t.rootkey())

