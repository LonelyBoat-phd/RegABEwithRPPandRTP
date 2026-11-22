import copy
import gc
import unittest
from dataclasses import replace
from unittest.mock import patch
import regabe as r
from regabe import primitives as a,validation,core,garg_baseline as base
from regabe.indices import compact_set,unique_sums
from regabe.native_backend import FixedBase

class BackendTests(unittest.TestCase):
    def test_non_degenerate_symmetric_bilinear(self):
        g=a.G1;e=a.gt_pair(g,g)
        self.assertIs(a.G1,a.G2);self.assertNotEqual(e,a.FQ12.one())
        self.assertEqual(a.gt_pair(g**7,g**11),e**77)
        self.assertEqual(a.gt_pair(g**11,g**7),e**77)
        self.assertEqual(e**a.P,a.FQ12.one())
    def test_native_msm_and_double_scalar(self):
        points=[a.G1**i for i in range(1,12)];scalars=[0,1,-1,2,a.P-1,17,23,0,9,2,3]
        expected=a.g1_prod(a.g1_pow(p,s) for p,s in zip(points,scalars))
        self.assertEqual(a.GROUP.msm(points,scalars),expected)
        self.assertEqual(a.double_scalar(points[0],7,points[1],-3),a.G1)
    def test_fixed_base_boundary_scalars(self):
        table=FixedBase(a.G1)
        for k in [0,1,-1,19,a.P,a.P+1]:self.assertEqual(table.multiply(k),a.G1**k)
    def test_product_pairing_and_identities(self):
        terms=[(a.G1,a.G1**3),(a.G1**2,a.G1**5),(a.Z1,a.G1),(a.G1,a.Z1)]
        self.assertEqual(a.pair_product(terms),a.gt_prod(a.gt_pair(x,y) for x,y in terms))
        self.assertEqual(a.pair_product([]),a.FQ12.one())
    def test_encoding_membership_and_immutability(self):
        for x in [a.Z1,a.G1,a.G1**19]:self.assertEqual(a.GROUP.decode(x.serialize()),x)
        self.assertEqual(a.GROUP.decode(a.FQ12.one().serialize(),1),a.FQ12.one())
        # Finite point (0,0) has order 2, NOT the required prime-order subgroup.
        with self.assertRaises(ValueError):a.GROUP.decode(b'\x01'+bytes(a.G1_BYTES-1))
        with self.assertRaises(ValueError):a.GROUP.decode(a.G1.serialize()[:-1])
        with self.assertRaises(AttributeError):a.G1.kind=1
        self.assertIs(copy.deepcopy(a.G1),a.G1)
        a.member_g1(a.Z1);a.member_gt(a.FQ12.one())
    def test_context_and_element_lifetime(self):
        from regabe.native_backend import Type1
        other=Type1(a.GROUP.path);point=other.g**7
        del other;gc.collect()
        self.assertTrue(point._ctx.member(point,0))
        with self.assertRaises(TypeError):a.GROUP.pair(a.G1,point)

class IndexTests(unittest.TestCase):
    def test_compact_properties_and_unique_sums(self):
        for L,expected in [(16,65),(32,211),(64,665)]:
            d=compact_set(L);values=set(d)
            self.assertEqual(len(values),L)
            self.assertTrue(all(2*x not in values for x in d))
            self.assertTrue(all(x==y or x+y!=2*z for x in d for y in d for z in d))
            self.assertEqual(len(unique_sums(d)),expected)
            self.assertEqual(d,base.progression_set(L))
    def test_shared_W(self):
        sp,_=a.setup(4,1)
        self.assertEqual(len({id(x) for x in sp.W.values()}),len(unique_sums(sp.d)))
        for (i,j),w in sp.W.items():
            self.assertEqual(a.gt_pair(sp.U[i],sp.A[j]),a.gt_pair(sp.g1,w))

class ValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.x=r.build(3,3,exclude_isvalid=True)
    def test_default_admission_uses_one_global_round_and_compact_record(self):
        with patch.object(validation, '_global_round', wraps=validation._global_round) as check:
            x = r.build(2, 1, profiles=((0,), (1,)), exclude_isvalid=True)
        self.assertEqual(check.call_count, 1)
        with patch.object(validation, '_global_round', wraps=validation._global_round) as check:
            self.assertEqual(r.all_y_check(x.parameters, x.registrations), [])
        self.assertEqual(check.call_count, 1)
        for record in x.registrations:
            self.assertEqual(record.splits, ())
            self.assertEqual(len(record.responses), 1)
            self.assertEqual(len(record.responses[0]), 5)
            self.assertTrue(a.verify_registration(x.parameters, record))

    def test_global_native_equals_naive(self):
        self.assertTrue(a.global_y_check(self.x.parameters,self.x.registrations))
        self.assertTrue(a.global_y_check(self.x.parameters,self.x.registrations,msm_method='naive'))
    def test_one_error_rejects_without_diagnostics(self):
        regs=copy.deepcopy(self.x.registrations);sp=self.x.parameters
        regs[1].Y[0,1][1]*=sp.g2
        with patch.object(validation,'diagnose_snapshot',side_effect=AssertionError('diagnostics ran')):
            with self.assertRaises(a.BatchFailure):a.global_y_check(sp,regs)
    def test_diagnostics_receiver_submitter_attribute(self):
        regs=copy.deepcopy(self.x.registrations);sp=self.x.parameters
        regs[1].Y[0,1][1]*=sp.g2
        with self.assertRaises(a.BatchFailure) as caught:a.global_y_check(sp,regs,diagnose=True)
        self.assertIn((0,1,1),caught.exception.errors)
    def test_cancelling_errors_show_why_private_weights_are_needed(self):
        regs=copy.deepcopy(self.x.registrations);sp=self.x.parameters
        regs[1].Y[0,1][0]*=sp.g2;regs[1].Y[0,1][1]*=a.neg(sp.g2)
        # Fixture only: all-one coefficients make these malformed relations cancel.
        with patch.object(a.secrets,'randbelow',return_value=0):
            self.assertTrue(validation._global_round(sp,regs,'native'))
        # Different coefficients for the first two erroneous relations force rejection.
        n=sp.ctx.L*(sp.ctx.L-1)*sp.ctx.u
        values=[0]*n;values[1]=1
        with patch.object(a.secrets,'randbelow',side_effect=values):
            self.assertFalse(validation._global_round(sp,regs,'native'))
    def test_failed_global_never_accepted_if_diagnosis_empty(self):
        with patch.object(validation,'_global_round',return_value=False),patch.object(validation,'diagnose_snapshot',return_value=[]):
            with self.assertRaises(a.BatchFailure):a.global_y_check(self.x.parameters,self.x.registrations,diagnose=True)
    def test_capability_receipt_is_bound_to_key_and_parameters(self):
        sp,issuer=a.setup(2,1);sec,pub=a.source_keygen(sp,0);receipt=a.validate_source(sp,pub)
        with patch.object(a,'source_key_valid',side_effect=AssertionError('IsValid inside measured phase')):
            e=a.generate_registration(sp,issuer,0,[0],sec,pub,source_receipt=receipt)
            self.assertTrue(a.verify_registration(sp,e.public,source_receipt=receipt))
        changed=copy.deepcopy(pub);changed.Q*=sp.g2
        self.assertFalse(a._source_valid_or_receipt(sp,changed,receipt))
        sp.A[1]*=sp.g2
        self.assertFalse(a._source_valid_or_receipt(sp,pub,receipt))
        self.assertFalse(a._source_valid_or_receipt(sp,pub,a._SourceReceipt()))
    def test_invalid_proof_and_certificate(self):
        reg=self.x.registrations[0]
        reg=replace(reg, challenge=(reg.challenge+1)%a.P)
        with self.assertRaises(a.InvalidProof):a.verify_registration(self.x.parameters,reg)
        reg=copy.deepcopy(self.x.registrations[0]);reg.certificate.signature=bytes(64)
        with self.assertRaises(a.InvalidCertificate):a.verify_registration(self.x.parameters,reg)

class ProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.x=r.build(2,3,profiles=((0,0,1),(0,0,0)),exclude_isvalid=True)
    def test_general_and_repeated_label_reference(self):
        x=self.x
        for p in [r.all_attributes_and([0,1],a.P),r.Policy([[1,1],[0,a.P-1]],[0,0])]:
            mu=x.kc.public.omega**123
            ct=r.encrypt(x.kc.sender_input(x.board,p.rho),p,mu,x.board.trust,latest=x.board.latest)
            for user in x.users:
                dm=x.kc.decrypt_input(x.board,user.slot,user.labels(p),ct.head)
                for mode in ['shift','cached','v02']:
                    self.assertEqual(user.decrypt(dm,ct,mask_mode=mode),mu)
                self.assertEqual(user.decrypt(dm,ct,optimized=False),mu)
    def test_zero_encryption_coins(self):
        x=self.x;p=r.all_attributes_and([0,1],a.P)
        with patch.object(a,'rand_scalar',return_value=0):
            ct=r.encrypt(x.kc.sender_input(x.board,p.rho),p,a.FQ12.one(),x.board.trust,latest=x.board.latest)
        u=x.users[0];dm=x.kc.decrypt_input(x.board,0,u.labels(p),ct.head)
        self.assertEqual(u.decrypt(dm,ct),a.FQ12.one())
    def test_target_withdrawal_unaffected_attribute_and_history(self):
        x=r.build(2,2,exclude_isvalid=True);p=r.all_attributes_and([0,1],a.P);mu=x.kc.public.omega**17
        old=x.users[0].checkpoint();ct=r.encrypt(x.kc.sender_input(x.board,p.rho),p,mu,x.board.trust,latest=x.board.latest)
        dm=x.kc.decrypt_input(x.board,0,old.labels(p),ct.head)
        _,receipt=r.revoke(x,0,0)
        for user in x.users:
            sync=x.kc.sync_input(user.slot,receipt.head.digest)
            self.assertTrue(user.catch_up(sync));self.assertFalse(user.catch_up(sync))
        self.assertEqual(x.users[0].bits,(1,0));self.assertEqual(x.users[1].bits,(0,0))
        with self.assertRaises(a.UnsatisfiedPolicy):x.users[0].labels(p)
        remaining=r.all_attributes_and([1],a.P)
        fresh=r.encrypt(x.kc.sender_input(x.board,remaining.rho),remaining,mu,x.board.trust,latest=x.board.latest)
        user=x.users[0]
        self.assertEqual(user.decrypt(x.kc.decrypt_input(x.board,0,user.labels(remaining),fresh.head),fresh),mu)
        self.assertEqual(old.decrypt(dm,ct),mu)
        with self.assertRaises(core.ProtocolError):user.decrypt(dm,ct)
    def test_replay_signatures_and_wrong_coordinate(self):
        x=r.build(2,1,exclude_isvalid=True);_,receipt=r.revoke(x,1,0)
        own=x.kc.sync_input(0,receipt.head.digest);user=x.users[0]
        bad=replace(own,commit=replace(own.commit,auth=replace(own.commit.auth,ra=bytes(64))))
        before=(user.head,user.bits,user._xi)
        with self.assertRaises(a.AuthorizationFailure):user.catch_up(bad)
        self.assertEqual((user.head,user.bits,user._xi),before)
        with self.assertRaises(core.ProtocolError):x.users[1].catch_up(own)
        self.assertTrue(user.catch_up(own))
    def test_snapshot_commit_and_parent_CAS(self):
        x=r.build(2,2,exclude_isvalid=True)
        p0=x.kc.prepare_with(x.ra,0,0);p1=x.kc.prepare_with(x.ra,1,0)
        checked=x.kc.validate(p0);other=x.kc.validate(p1);du=p0.du
        object.__setattr__(p0,'du',p0.du*x.parameters.g1)
        with self.assertRaises(a.RegABEError):x.kc.validate(p0)
        receipt=x.kc.commit(x.board,checked);x.ra.accept_commit(receipt,x.board.trust)
        self.assertEqual(x.kc.sync_input(0,receipt.head.digest).du,du)
        with self.assertRaises(core.ProtocolError):x.kc.commit(x.board,other)
    def test_fixed_RA_equivalence(self):
        x=self.x;fast=core.RA(x.parameters,((0,)*3,)*2);slow=core.RA(x.parameters,((0,)*3,)*2,fixed_base=False)
        slow._root,slow._keys=fast._root,fast._keys
        parent,block=x.kc.revocation_material(0);fast._head=slow._head=parent.digest
        f=fast.prepare(parent,block,0,0,b'z'*64);s=slow.prepare(parent,block,0,0,b'z'*64)
        self.assertEqual(f[:3],s[:3]);self.assertEqual(f[3].descriptor,s[3].descriptor)
    def test_baseline_and_sizes(self):
        pp=base.setup(2,2);pairs=[base.keygen(pp,i) for i in range(2)]
        self.assertTrue(all(base.is_valid(pp,pub) for sec,pub in pairs))
        agg=base.aggregate(pp,[p for s,p in pairs],((0,0),(0,0)));user=base.User(agg,pairs[0][0])
        p=r.all_attributes_and([0,1],a.P);mu=pp.Omega**29;ct=base.encrypt(agg,p,mu)
        self.assertEqual(user.decrypt(ct),mu);self.assertEqual(user.decrypt(ct,optimized=False),mu)
        self.assertEqual(r.material_sizes([a.G1,a.FQ12.one()])['group_bytes'],a.G1_BYTES+a.GT_BYTES)

class MeasurementTests(unittest.TestCase):
    def test_isvalid_outside_every_ours_measured_phase(self):
        inside=[False];calls=[];original=a.source_key_valid;metrics=[]
        def isvalid(sp,pub):
            self.assertFalse(inside[0],'source IsValid leaked into a timed phase')
            calls.append(pub.slot);return original(sp,pub)
        def timer(name,fn):
            inside[0]=True
            try:result=fn()
            finally:inside[0]=False
            metrics.append(name);return result
        with patch.object(a,'source_key_valid',side_effect=isvalid):
            r.build(2,1,timer=timer,exclude_isvalid=True,user_slots=(0,))
        self.assertEqual(calls,[0,1]);self.assertNotIn('source_validate',metrics)
        self.assertIn('freeze_with_admission_checks',metrics)
    def test_baseline_isvalid_is_untimed(self):
        import bench
        inside=[False];original=a.source_key_valid;original_timed=bench.timed;calls=[]
        def isvalid(pp,pub):
            self.assertFalse(inside[0]);calls.append(pub.slot);return original(pp,pub)
        def timer(rows,name,fn):
            inside[0]=True
            try:return original_timed(rows,name,fn)
            finally:inside[0]=False
        with patch.object(a,'source_key_valid',side_effect=isvalid),patch.object(bench,'timed',side_effect=timer):
            bench.baseline_round(2,1)
        self.assertEqual(calls,[0,1])

if __name__=='__main__':unittest.main()
