#!/usr/bin/env python3
"""Build the bundled PBC library and bridge in one shared object (Linux/WSL)."""
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import tarfile

ROOT=Path(__file__).resolve().parent.parent
def main():
    archive=ROOT/'vendor/pbc-0.5.14.tar.gz'
    expected=(ROOT/'vendor/SHA256SUMS').read_text().split()[0]
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=expected:raise SystemExit('PBC source checksum mismatch')
    build=ROOT/'build';build.mkdir(exist_ok=True)
    with tarfile.open(archive) as tf:tf.extractall(build,filter='data')
    source=build/'pbc-0.5.14'
    sources=re.findall(r'[A-Za-z_]+/[A-Za-z_0-9]+\.c',(source/'Makefile.am').read_text().split('libpbc_la_SOURCES =',1)[1].split('libpbc_la_LDFLAGS',1)[0])
    flags=os.environ.get('REGABE_BUILD_CPPFLAGS','').split()
    libraries=os.environ.get('REGABE_BUILD_LIBS','-lgmp -lm').split()
    cmd=[os.environ.get('CC','cc'),'-shared','-fPIC','-O3','-I'+str(source/'include'),'-I'+str(source),*flags,
         str(ROOT/'native/type1.c'),*[str(source/p) for p in sources],*libraries,'-o',str(ROOT/'native/libregabe_type1.so')]
    subprocess.run(cmd,check=True)
    (ROOT/'native/build-info.json').write_text(json.dumps({
        'compiler':subprocess.check_output([os.environ.get('CC','cc'),'--version'],text=True).splitlines()[0],
        'pbc_source_sha256':expected,'optimization':'-O3','command':[part.replace(str(ROOT), '${PROJECT_ROOT}') for part in cmd]},indent=2)+'\n')
    print('Built native/libregabe_type1.so')
if __name__=='__main__':main()
