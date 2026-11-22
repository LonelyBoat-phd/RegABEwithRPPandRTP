import copy
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from regabe import primitives as a, core as c
from regabe.native_backend import Element,ffi
from supplement import optimization as o,protocol as p

class OptimizationTests(unittest.TestCase):
    def test_exact_native_membership_rejects_torsion_and_wrong_context(self):
        a.GROUP.member_many([a.Z1,a.G1,a.G1**19])
        bad=Element(a.GROUP,a.GROUP.lib.ra_decode(a.GROUP._ptr,0,bytes(a.G1_BYTES-1)),0)
        with self.assertRaises(ValueError):a.GROUP.member_many([a.G1,bad,a.G1])
        with self.assertRaises(TypeError):a.GROUP.member_many([a.FQ12.one()])
        self.assertEqual(a.GROUP.product([]),a.Z1)
    def test_native_msm_windows_boundary_scalars(self):
        for n in (0,1,17,65):
            points=[a.G1**(i+1) for i in range(n)]
            scalars=[(0,1,-1,a.P-1,a.P,a.P+1)[i%6] for i in range(n)]
            want=a.Z1
            for point,k in zip(points,scalars):want=want*a.g1_pow(point,k)
            for width in range(2,11):self.assertEqual(a.GROUP.msm(points,scalars,width),want)
    def test_global_layouts_equal_reference_with_same_weights(self):
        from regabe.validation import _global_round
        sp=SimpleNamespace(ctx=SimpleNamespace(L=3,u=2),g1=a.G1,A=tuple(a.G1**(i+1) for i in range(3)))
        regs=[]
        for j in range(3):
            x=tuple(a.G1**(10*j+w+1) for w in range(2))
            regs.append(SimpleNamespace(X=x,Y={(i,j):tuple(v**(i+1) for v in x) for i in range(3) if i!=j}))
        original=o.options()
        try:
            for corrupted in (False,True):
                if corrupted:
                    row=list(regs[0].Y[1,0]);row[0]*=a.G1;regs[0].Y[1,0]=tuple(row)
                weights=list(range(12))
                with patch.object(a.secrets,'randbelow',side_effect=weights):want=_global_round(sp,regs,'auto')
                self.assertEqual(want,not corrupted)
                for layout in ('receiver','merged'):
                    o._CONFIG['y_layout']=layout
                    with patch.object(a.secrets,'randbelow',side_effect=weights) as draw:
                        self.assertEqual(o.global_round(sp,regs),want)
                        self.assertEqual(draw.call_count,12)
        finally:o._CONFIG.clear();o._CONFIG.update(original)
    def test_cached_wire_replacement_and_deepcopy(self):
        meta=c.Meta(b'p',b's',b'c',3,2)
        evt=c.Event(meta,0,b'x'*32,0,1,0,1,b'n'*64)
        expected=c.seq([meta.wire(),a.i2b(0,4),b'x'*32,a.i2b(0,8),a.i2b(1,8),a.i2b(0,8),a.i2b(1,8),b'n'*64])
        self.assertEqual(evt.wire(),expected)
        self.assertEqual(evt.digest,a.sha256(b'EVT',expected))
        self.assertEqual(copy.deepcopy(evt).wire(),expected)
        self.assertNotEqual(replace(evt,nonce=b'z'*64).digest,evt.digest)
    def test_proof_modes_and_nested_timing(self):
        from supplement.run import fixture
        original=o.options()
        try:
            for mode in ('double','fixed'):
                o._CONFIG['proof']=mode
                sp,b,sec,wit,agg,metrics=fixture(3,2,42)
                m=metrics['Private']
                self.assertGreater(m['record_proof_reconstruct_s'],0)
                self.assertGreaterEqual(m['aggregate_residual_s'],0)
        finally:o._CONFIG.clear();o._CONFIG.update(original)
if __name__=='__main__':unittest.main()
