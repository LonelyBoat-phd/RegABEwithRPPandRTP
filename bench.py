#!/usr/bin/env python3
"""Serial Type-1 comparison. AND-only workload; source IsValid is untimed."""
from pathlib import Path
import argparse
import hashlib
import json
import platform
import statistics
import sys
import time
import importlib.metadata

import regabe as r
from regabe import primitives as a,garg_baseline as base
from regabe.indices import unique_sums
from regabe.native_backend import ffi

def timed(rows,name,fn):
    start=time.perf_counter();value=fn();rows.setdefault(name,[]).append(time.perf_counter()-start);return value

def summarize(values):
    values=list(values)
    return {'n':len(values),'mean_seconds':statistics.mean(values),'median_seconds':statistics.median(values),
            'stdev_seconds':statistics.stdev(values) if len(values)>1 else 0.0,'samples_seconds':values}

def environment():
    root=Path(__file__).resolve().parent
    h=hashlib.sha256()
    for path in sorted((root/'regabe').glob('*.py'))+[root/'native/type1.c',root/'bench.py']:
        h.update(str(path.relative_to(root)).encode()+b'\0'+path.read_bytes())
    return {'backend':a.BACKEND,'python':sys.version,'platform':platform.platform(),
            'cffi':importlib.metadata.version('cffi'),'cryptography':importlib.metadata.version('cryptography'),
            'source_sha256':h.hexdigest(),'parameter_sha256':a.GROUP.parameter_sha256,
            'native_library_sha256':hashlib.sha256((root/'native/libregabe_type1.so').read_bytes()).hexdigest(),
            'pbc':'0.5.14','gmp':ffi.string(a.GROUP.lib.ra_gmp_version()).decode(),
            'r_bits':a.P.bit_length(),'q_bits':a.GROUP.q.bit_length(),'embedding_degree':2,
            'G_encoding_bytes':a.G1_BYTES,'GT_encoding_bytes':a.GT_BYTES,'parallel':False}

def ours_round(L,u):
    rows={};timer=lambda name,fn:timed(rows,name,fn)
    x=r.build(L,u,timer=timer,user_slots=(0,),exclude_isvalid=True)
    p=r.all_attributes_and(range(u),a.P);message=x.kc.public.omega**123
    sender=timer('sender_fetch',lambda:x.kc.sender_input(x.board,p.rho))
    ct=timer('Encrypt',lambda:r.encrypt(sender,p,message,x.board.trust,latest=x.board.latest))
    user=x.users[0]
    labels=timer('cold_policy_reconstruction',lambda:user.labels(p))
    material=timer('decrypt_fetch',lambda:x.kc.decrypt_input(x.board,0,labels,ct.head))
    actual=timer('Decrypt_warm',lambda:user.decrypt(material,ct))
    if actual!=message:raise AssertionError('ours decryption')
    return {k:sum(v) for k,v in rows.items()},r.material_sizes(material)

def baseline_round(L,u):
    rows={};timer=lambda name,fn:timed(rows,name,fn)
    pp=timer('setup',lambda:base.setup(L,u,set_mode='compact'));keys=[];secrets=[]
    for i in range(L):
        sec,pub=timer('source_keygen',lambda:base.keygen(pp,i));secrets.append(sec);keys.append(pub)
        # Deliberately outside every measured function. Never silently skip input validation.
        if not base.is_valid(pp,pub):raise AssertionError('baseline IsValid')
    agg=timer('Aggregate',lambda:base.aggregate(pp,keys,tuple((0,)*u for _ in range(L))))
    user=timer('user_initialize_with_cache',lambda:base.User(agg,secrets[0]))
    p=r.all_attributes_and(range(u),a.P);message=pp.Omega**123
    ct=timer('Encrypt',lambda:base.encrypt(agg,p,message))
    timer('cold_policy_reconstruction',lambda:user.selected(p))
    actual=timer('Decrypt_warm',lambda:user.decrypt(ct))
    if actual!=message:raise AssertionError('baseline decryption')
    return {k:sum(v) for k,v in rows.items()},{}

def run(L,u,repeats,warmups):
    if min(L-1,u,repeats)<1 or warmups<0:raise ValueError('invalid dimensions/repeats')
    samples={'ours':{},'baseline':{}};sizes={}
    for round_no in range(warmups+repeats):
        order=('ours','baseline') if round_no%2==0 else ('baseline','ours')
        for name in order:
            print(f'{name} L={L} u={u} round={round_no+1}/{warmups+repeats}',file=sys.stderr,flush=True)
            metrics,sizes_now=(ours_round if name=='ours' else baseline_round)(L,u)
            if round_no>=warmups:
                for k,v in metrics.items():samples[name].setdefault(k,[]).append(v)
                if sizes_now:sizes[name]=sizes_now
    indices=base.progression_set(L,'compact')
    return {'L':L,'u':u,'repeats':repeats,'warmups':warmups,'environment':environment(),
            'policy':{'kind':'all_attributes_AND','K':u,'columns':u},
            'indices':{'kind':'compact','dmax':3*max(indices),'unique_W':len(unique_sums(indices))},
            'scope':{'source_IsValid':'executed outside timing for both schemes; no IsValid metric',
                     'registration_proof_validation':'included','Y_membership':'included',
                     'YCheck':'one global pass with independent private nonzero random weights',
                     'weights_output':False,'failure_localization_in_normal_benchmark':False,
                     'Aggregate_ours':'freeze_with_admission_checks; excludes source IsValid, includes proof/Y checks and roots',
                     'Decrypt_warm':'cached reconstruction; membership/authentication still included',
                     'end_to_end_total':'not reported: excluded validation lies between measured phases'},
            'material_sizes':sizes,'metrics':{name:{k:summarize(v) for k,v in m.items()} for name,m in samples.items()}}

def cli():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--L',type=int,nargs='+',default=[2]);parser.add_argument('--u',type=int,nargs='+',default=[2])
    parser.add_argument('--repeats',type=int,default=50);parser.add_argument('--warmups',type=int,default=10)
    parser.add_argument('--reference-grid',action='store_true');parser.add_argument('--output',default='results/comparison.json')
    args=parser.parse_args()
    ls,us=([16,32],[32,64,128]) if args.reference_grid else (args.L,args.u)
    if len(set(ls))!=len(ls) or len(set(us))!=len(us):parser.error('duplicate dimensions')
    if any(L<2 for L in ls) or any(u<1 for u in us) or args.repeats<1 or args.warmups<0:parser.error('invalid arguments')
    results=[run(L,u,args.repeats,args.warmups) for L in ls for u in us]
    path=Path(args.output);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps({'configurations':results},indent=2)+'\n')
    print(path)
if __name__=='__main__':cli()
