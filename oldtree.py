import json
# my tree implementation

class Tree:
    nodes={}
    idf=None # id field, e.g. 'name' or 'id', must be unique
    pf=None # parent field e.g. 'parent'. child pf must be equal to idf of parent 
    pathf=None # path element, must be unique among children of parent
    valuef=None
    separator=':'
    d=None #tree as dict
    
    def __init__(self, idf='id', pf='parent',pathf='name',separator=':',valuef='value'):
        self.idf=idf
        self.pf=pf
        self.pathf=pathf
        self.separator=separator
        self.valuef=valuef
        self.d=None

    
    def getdict(self,parentid=None):
        # if we already have dict, return it

        def resolvedict(d,path='',depth=5):
            if depth==0:
                return None
           
            # walk this path
            if path:
                subd=d
                for pelem in path.split(self.separator):
                    if pelem in subd:
                        subd = subd[pelem]
                    else:
                        return dict()
            else:
                subd=d
            
            # now subd is part
           
            dd={}
            
            # first - speccommands
            for k in subd:
                if k.startswith('@'):
                    spec = k.split(' ')
                    if spec[0]=='@include':
                        # get subdict
                        isubd = resolvedict(d,spec[1],depth-1)
                        if isubd is not None:
                            #print "isubd:",isubd
                            #print json.dumps(isubd,indent=4)
                            for kk in isubd:
                                dd[kk]=isubd[kk]
                    elif spec[0]=='@access':
                        pass
                    else:
                        print "!!! unknown special command '{}'".format(spec[0])
                        # simulate string
                        dd[k] = subd[k]

            # now other keys                                    
            for k in subd:
                if isinstance(subd[k],dict):                                        
                    # calc subpath
                    if path:
                        subpath = path+self.separator+k
                    else:
                        subpath = k
                    dd[k]=resolvedict(d,subpath,depth) #resolve same depth
                elif isinstance(subd[k],basestring):
                    dd[k]=subd[k]
                elif isinstance(subd[k],type(None)):
                    dd[k]=None
            return dd    
        # end of resolvedict

        # main part of getdict
        if self.d:
            return self.d
                        
        d={}
        for ch in self.children(parentid):
            if getattr(ch,self.valuef):
                # key = value
                d[getattr(ch,self.pathf)]=getattr(ch,self.valuef)
            else:
                # no value => subtree
                d[getattr(ch,self.pathf)]=self.getdict(getattr(ch,self.idf))
            
        if d:        
            if parentid is None:        
                # resolve dict            
                #print "dict before resolve",json.dumps(d,indent=4)
                dd = resolvedict(d)
                #print "dict after resolve",json.dumps(dd,indent=4)
                self.d = dd
                return dd
            else:
                return d
        else:            
            return ''

    
    def dump(self,parent=None,prefix=''):
        #print "tree dump parent: {} (id: '{}', parent: '{}', prefix: '{}')".format(parent,self.idf,self.pf,prefix)
        # find this node        
        print "dump old"
        for nid,n in self.nodes.items():
            #np = getattr(n,self.pf)
            #print "try node {}, parent: {}".format(n,np)
            if getattr(n,self.pf) == parent:                
                print prefix+getattr(n,self.pathf)+'='+getattr(n,self.valuef)
                self.dump(nid,prefix+'. ')     
        

    
    def nodebyparent(self,parent_id=None):
        for nid,n in self.nodes.items():
            if getattr(n,self.pf) == parent_id:
                return n    
        return None
            
    def rootnode(self):
        return self.nodebyparent()
    
    def children(self,pid):
        for nid,n in self.nodes.items():
            if getattr(n,self.pf) == pid:
                yield n
    
    def add(self,node):
        # check if node has required fields
        if not hasattr(node,self.idf):
            print "ERROR. must have id field '{}'".format(self.idf)
        if not hasattr(node,self.pf):
            print "ERROR. must have parent field '{}'".format(self.pf)
        if not hasattr(node,self.pathf):
            print "ERROR. must have path field '{}'".format(self.pathf)
        
        self.nodes[getattr(node,self.idf)]=node
        self.d = None

                  
    def getkey(self,path,subdict=None,pathval=None):
                
      
        # print "TREE getkey '{}'".format(path)          
                
                
        if subdict is None:
            d = self.getdict()
        else:
            d = subdict
        
        # print "FROM dict:",d


        if not path:
            # return full subdict
            return d
        
        if pathval is None:
            pathval={}
            
        patha = path.split(self.separator)
        rempath = list(patha)
        
        # look for patha[0]
        for k in d:
            if k in patha:
                pathval[k]=d[k]               
        
        if len(patha)==1:
            # last item
            if path in pathval:
                return pathval[path]
            return None
        else:
            try:
                print "recursive getkey"
                keyval = self.getkey(':'.join(patha[1:]),pathval[patha[0]],pathval)
            except KeyError:
                return None

            print "TREE RETURN:",keyval
            return keyval
        

    def getkeydb(self,path,incdepth=5):
        pathval={}
        print "## getkey '{}'".format(path)
        patha = path.split(self.separator)
        print "patha:",patha
        itemname=patha[-1]
        print "item: {}".format(itemname)
    
        d=self.mkdict()
        print "dict: {}".format(d)

        pnodeid=None        
        for p in patha:
            print "will look for path {}".format(p)
            for n in self.children(pnodeid):
                npath = getattr(n,self.pathf)
                print "({}) check npath {}".format(p,npath)
                if npath in patha:
                    print "found npath {}".format(npath)
                    pathval[npath]=n
                if npath==p:
                    print "Will enter {}".format(p)
                    pnodeid = getattr(n,self.idf)
                    
        print pathval
        if itemname in pathval:
             return getattr(pathval[itemname],self.valuef)
        return None
        
        
