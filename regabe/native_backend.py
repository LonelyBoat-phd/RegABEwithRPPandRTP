"""Immutable Python objects over PBC Type A, via a small CFFI ABI bridge."""
from pathlib import Path
import hashlib
import os
import secrets
from cffi import FFI

ROOT=Path(__file__).resolve().parent.parent
ffi=FFI()
ffi.cdef('''
const char *ra_gmp_version(void); int ra_prime(const char *);
void *ra_ctx(const char *); void ra_ctx_free(void *); void ra_free(void *);
void *ra_identity(void *,int); void *ra_hash(void *,const unsigned char *,int);
void *ra_mul(void *,void *); void *ra_inv(void *); void *ra_pow(void *,const char *);
void *ra_pow2(void *,const char *,void *,const char *);
int ra_member_many(void *,void **,int,const char *,const char *);
void *ra_product(void *,void **,int);
int ra_equal(void *,void *); int ra_unit(void *); int ra_length(void *);
int ra_encode(unsigned char *,void *); void *ra_decode(void *,int,const unsigned char *);
int ra_curve(void *,const char *); void *ra_pair(void *,void *);
void *ra_pair_product(void *,void **,void **,int);
void *ra_table(void *); void ra_table_free(void *); void *ra_table_pow(void *,const char *);
void *ra_msm(void *,void **,const char **,int,int);
char *ra_params(int,int); void ra_string_free(void *);
''')

def load_library():
    path=Path(os.environ.get('REGABE_TYPE1_LIB',str(ROOT/'native/libregabe_type1.so')))
    if not path.is_file():
        raise RuntimeError('Native backend missing. Run: python tools/build_native.py')
    return ffi.dlopen(str(path))

def hexint(x):return format(int(x),'x').encode()

class Element:
    __slots__=('_ctx','_ptr','kind','_bytes')
    def __init__(self,ctx,ptr,kind):
        if ptr==ffi.NULL:raise MemoryError('PBC allocation')
        object.__setattr__(self,'_ctx',ctx)
        object.__setattr__(self,'_ptr',ffi.gc(ptr,ctx.lib.ra_free))
        object.__setattr__(self,'kind',kind)
        object.__setattr__(self,'_bytes',None)
    def __setattr__(self,*_):raise AttributeError('immutable group element')
    def __deepcopy__(self,memo):return self
    def __copy__(self):return self
    def _match(self,other):
        if not isinstance(other,Element) or other._ctx is not self._ctx or other.kind!=self.kind:
            raise TypeError('group/context mismatch')
    def __eq__(self,other):
        return isinstance(other,Element) and other._ctx is self._ctx and other.kind==self.kind and bool(self._ctx.lib.ra_equal(self._ptr,other._ptr))
    def __mul__(self,other):
        self._match(other);return Element(self._ctx,self._ctx.lib.ra_mul(self._ptr,other._ptr),self.kind)
    def __truediv__(self,other):return self*other.inverse()
    def inverse(self):return Element(self._ctx,self._ctx.lib.ra_inv(self._ptr),self.kind)
    def raw_pow(self,n):
        if n<0:return self.inverse().raw_pow(-n)
        return Element(self._ctx,self._ctx.lib.ra_pow(self._ptr,hexint(n)),self.kind)
    def __pow__(self,n):return self.raw_pow(int(n)%self._ctx.r)
    def serialize(self):
        if self._bytes is None:
            n=self._ctx.lib.ra_length(self._ptr);buf=ffi.new('unsigned char[]',n)
            if self._ctx.lib.ra_encode(buf,self._ptr)!=n:raise ValueError('encoding length')
            raw=bytes(ffi.buffer(buf,n))
            if self.kind==0:
                raw=(b'\x00'+bytes(n)) if self._ctx.lib.ra_unit(self._ptr) else b'\x01'+raw
            else:raw=b'\x02'+raw
            object.__setattr__(self,'_bytes',raw)
        return self._bytes
    def __repr__(self):return f'<Type1 {"G" if self.kind==0 else "GT"} {hashlib.sha256(self.serialize()).hexdigest()[:12]}>'

class FixedBase:
    def __init__(self,base):
        self.base=base;self._ctx=base._ctx
        self._ptr=ffi.gc(self._ctx.lib.ra_table(base._ptr),self._ctx.lib.ra_table_free)
    def multiply(self,n):
        return Element(self._ctx,self._ctx.lib.ra_table_pow(self._ptr,hexint(int(n)%self._ctx.r)),self.base.kind)

class Type1:
    def __init__(self,path):
        self.lib=load_library();self.path=Path(path);self.parameter_bytes=self.path.read_bytes()
        fields={line.split()[0]:line.split()[1] for line in self.parameter_bytes.decode().splitlines() if len(line.split())==2}
        if fields.get('type')!='a':raise ValueError('Only PBC prime-order Type A parameters are accepted')
        self.r=int(fields['r']);self.q=int(fields['q'])
        if self.r<=2 or self.q%12!=11 or (self.q+1)%self.r or int(fields['h'])<1 or int(fields['h'])*self.r!=self.q+1:
            raise ValueError('invalid Type A parameter relation')
        if not self.lib.ra_prime(hexint(self.r)) or not self.lib.ra_prime(hexint(self.q)):
            raise ValueError('nonprime Type A parameters')
        ptr=self.lib.ra_ctx(self.parameter_bytes)
        if ptr==ffi.NULL:raise ValueError('PBC rejected symmetric parameters')
        self._ptr=ffi.gc(ptr,self.lib.ra_ctx_free)
        self.parameter_sha256=hashlib.sha256(self.parameter_bytes).hexdigest()
        self.zero=self.identity(0);self.one=self.identity(1)
        self.g=self.hash_point(b'REGABE-TYPE1-GENERATOR'+bytes.fromhex(self.parameter_sha256))
        if self.pair(self.g,self.g)==self.one:raise ValueError('degenerate self-pairing')
    def identity(self,kind=0):return Element(self,self.lib.ra_identity(self._ptr,kind),kind)
    def hash_point(self,data):
        for counter in range(256):
            block=hashlib.sha512(b'REGABE-TYPE1-H2G'+len(data).to_bytes(8,'big')+data+counter.to_bytes(2,'big')).digest()
            p=Element(self,self.lib.ra_hash(self._ptr,block,len(block)),0)
            if p!=self.zero and self.member(p,0):return p
        raise ValueError('hash-to-group exhausted')
    def member(self,x,kind):
        if not isinstance(x,Element) or x._ctx is not self or x.kind!=kind:return False
        if kind==0 and not self.lib.ra_curve(x._ptr,hexint(self.q)):return False
        return x.raw_pow(self.r)==self.identity(kind)
    def member_many(self, points):
        points=tuple(points)
        for x in points:self._source(x)
        ptrs=ffi.new('void *[]',[x._ptr for x in points])
        bad=self.lib.ra_member_many(self._ptr,ptrs,len(points),hexint(self.q),hexint(self.r))
        if bad>=0:raise ValueError(f'nonmember at coordinate {bad}')
    def product(self, points):
        points=tuple(points)
        for x in points:self._source(x)
        ptrs=ffi.new('void *[]',[x._ptr for x in points])
        return Element(self,self.lib.ra_product(self._ptr,ptrs,len(points)),0)
    def pair(self,x,y):
        self._source(x);self._source(y)
        return Element(self,self.lib.ra_pair(x._ptr,y._ptr),1)
    def _source(self,x):
        if not isinstance(x,Element) or x._ctx is not self or x.kind!=0:raise TypeError('source group/context')
    def pair_product(self,terms):
        terms=tuple((x,y) for x,y in terms if x!=self.zero and y!=self.zero)
        for x,y in terms:self._source(x);self._source(y)
        xs=ffi.new('void *[]',[x._ptr for x,y in terms])
        ys=ffi.new('void *[]',[y._ptr for x,y in terms])
        return Element(self,self.lib.ra_pair_product(self._ptr,xs,ys,len(terms)),1)
    def msm(self,points,scalars,width=None):
        points=tuple(points);scalars=tuple(int(s)%self.r for s in scalars)
        if len(points)!=len(scalars):raise ValueError('MSM lengths')
        for x in points:self._source(x)
        if not points:return self.zero
        width=width or min(8,max(2,len(points).bit_length()-2))
        if not 2<=width<=10:raise ValueError('MSM window')
        xs=ffi.new('void *[]',[x._ptr for x in points])
        strings=[ffi.new('char[]',hexint(s)) for s in scalars]
        ss=ffi.new('const char *[]',strings)
        return Element(self,self.lib.ra_msm(self._ptr,xs,ss,len(points),width),0)
    def pow2(self,x,n,y,m):
        x._match(y)
        return Element(self,self.lib.ra_pow2(x._ptr,hexint(n%self.r),y._ptr,hexint(m%self.r)),x.kind)
    def decode(self,data,kind=0):
        n=self.lib.ra_length(self.identity(kind)._ptr)
        if len(data)!=n+1:raise ValueError('group encoding length')
        if kind==0 and data==b'\x00'+bytes(n):return self.zero
        if data[0]!=(1 if kind==0 else 2):raise ValueError('group encoding tag')
        x=Element(self,self.lib.ra_decode(self._ptr,kind,data[1:]),kind)
        if not self.member(x,kind) or x.serialize()!=data:raise ValueError('noncanonical/nonmember group element')
        return x

def generate_parameters(path,rbits=256,qbits=1536):
    if not 160<=rbits<=1024 or not max(rbits+32,512)<=qbits<=16384:raise ValueError('parameter sizes')
    lib=load_library();p=lib.ra_params(rbits,qbits)
    if p==ffi.NULL:raise RuntimeError('parameter generation failed')
    try:data=ffi.string(p)
    finally:lib.ra_string_free(p)
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
    return path
