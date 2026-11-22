"""Compatibility names: G1 and G2 are the SAME Type-1 source group."""
import os
from pathlib import Path
from .native_backend import Type1,FixedBase,Element,ROOT

PARAM_PATH=Path(os.environ.get('REGABE_PARAMS',str(ROOT/'params/type-a-256-1536.param')))
if not PARAM_PATH.is_file():raise RuntimeError('Missing parameter file; run python tools/generate_params.py')
GROUP=Type1(PARAM_PATH)
if GROUP.r.bit_length()+128>512:raise ValueError('Protocol CHI uses 512-bit HMAC; this profile requires r_bits <= 384')
curve_order=GROUP.r
field_modulus=GROUP.q
G1=G2=GROUP.g
Z1=Z2=GROUP.zero
b=b2=None

class FQ12:
    @staticmethod
    def one():return GROUP.one
    @staticmethod
    def zero():return None

def add(x,y):return x*y
def double(x):return x*x
def multiply(x,n):return x.raw_pow(int(n))
def neg(x):return x.inverse()
def eq(x,y):return x==y
def pairing(x,y):return GROUP.pair(y,x)
def is_inf(x):return isinstance(x,Element) and x.kind==0 and x==Z1
def is_on_curve(x,_):
    from .native_backend import hexint
    return isinstance(x,Element) and x._ctx is GROUP and x.kind==0 and bool(GROUP.lib.ra_curve(x._ptr,hexint(GROUP.q)))
def encode(x):return x.serialize()
def hash_point(msg,dst,unused=None):return GROUP.hash_point(dst+len(msg).to_bytes(8,'big')+msg)
