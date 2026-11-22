#!/usr/bin/env python3
"""Generate exact-size candidates; this command does not certify security."""
import argparse
from pathlib import Path
import runpy

ROOT=Path(__file__).resolve().parent.parent
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--rbits',type=int,default=256);p.add_argument('--qbits',type=int,default=1536)
    p.add_argument('--output',default=str(ROOT/'params/type-a-256-1536.param'))
    args=p.parse_args();m=runpy.run_path(str(ROOT/'regabe/native_backend.py'))
    for _ in range(256):
        path=m['generate_parameters'](args.output,args.rbits,args.qbits)
        fields={s.split()[0]:s.split()[1] for s in path.read_text().splitlines() if len(s.split())==2}
        if int(fields['r']).bit_length()==args.rbits and int(fields['q']).bit_length()==args.qbits:break
    else:raise SystemExit('Exact-size candidate generation exhausted')
    group=m['Type1'](path)
    print('Generated',path,'r_bits',group.r.bit_length(),'q_bits',group.q.bit_length(),'sha256',group.parameter_sha256)
if __name__=='__main__':main()
