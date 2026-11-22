import unittest
from dataclasses import replace
from unittest.mock import patch

from regabe import primitives as a, core as c
from regabe.policy import all_attributes_and
from supplement import protocol as p
from supplement.run import fixture, update_trial, check_access, access_trial, make_recipe


class SupplementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sp, cls.issuer = a.setup(3, 4)
        cls.keys = [a.source_keygen(cls.sp, i) for i in range(3)]
        cls.receipts = [a.validate_source(cls.sp, pub) for sec, pub in cls.keys]
        cls.bits = ((0, 0, 0, 0), (0, 1, 0, 1), (1, 0, 1, 0))

    def test_compact_proof_and_tamper(self):
        sec, pub = self.keys[0]
        reg, wit = p.generate_private(self.sp, self.issuer, sec, pub, self.bits[0])
        p.verify_record(self.sp, reg, self.receipts[0])
        self.assertEqual(len(reg.splits), 3)
        self.assertEqual(len(reg.responses), 4)
        self.assertTrue(a.verify_registration(self.sp, reg, source_receipt=self.receipts[0]))
        default = a.generate_registration(self.sp, self.issuer, 0, self.bits[0], sec, pub,
                                          source_receipt=self.receipts[0])
        p.verify_record(self.sp, default.public, self.receipts[0])
        self.assertEqual(len(default.public.wire(self.sp)), len(reg.wire(self.sp)))
        with self.assertRaises(c.ProtocolError):
            p.verify_record(self.sp, replace(reg, challenge=(reg.challenge + 1) % a.P), self.receipts[0])
        pubreg = p.generate_public(self.sp, self.issuer, sec, pub, self.bits[0])
        with self.assertRaises(c.ProtocolError):
            p.verify_record(self.sp, replace(pubreg, bits=(1, 0, 0, 0)), self.receipts[0])

    def test_formal_sample_counts(self):
        recipe = make_recipe('formal')
        self.assertEqual((recipe['warmups'], recipe['repeats']), (10, 50))
        self.assertEqual((recipe['update_events'], recipe['access_inner_repeats']), (16, 5))

    def test_u_one(self):
        sp, issuer = a.setup(2, 1)
        for bit in (0, 1):
            sec, pub = a.source_keygen(sp, 0)
            rec, _ = p.generate_private(sp, issuer, sec, pub, (bit,))
            self.assertEqual(rec.splits, ())
            p.verify_record(sp, rec, a.validate_source(sp, pub))

    def test_one_y_pass_and_update_correctness(self):
        from supplement import protocol
        with patch.object(protocol, '_global_round', wraps=protocol._global_round) as check:
            sp, b, sec, wit, agg, metrics = fixture(3, 4, 42)
            self.assertEqual(check.call_count, 1)
        for scheme in ('P', 'R', 'F'):
            group = 'P' if scheme == 'P' else 'Private'
            rt = p.runtime(sp, b, agg[group], sec, wit[group], scheme)
            check_access(rt, 4)
            attr = next(w for w in range(4) if b[1][w] == 0)
            ra, kc, board, users = rt
            packet, receipt = p.revoke(rt, 1, attr, {})
            mat0, mat1 = kc.sync_input(0, receipt.head.digest), kc.sync_input(1, receipt.head.digest)
            if scheme != 'F':
                corrupt = replace(packet, target=2)
                with self.assertRaises(c.ProtocolError):
                    users[0].catch_up(p.PublicSync(corrupt, receipt))
            self.assertTrue(users[0].catch_up(mat0)); self.assertTrue(users[1].catch_up(mat1))
            self.assertFalse(users[1].catch_up(mat1))
            self.assertEqual(users[1].bits[attr], 1)
            with self.assertRaises(a.UnsatisfiedPolicy):
                users[1].labels(all_attributes_and([attr], a.P))
            check_access(rt, 4)
        out = update_trial(sp, b, sec, wit, agg, 42, 4)
        self.assertEqual(set(out), {'R', 'F'})
        self.assertEqual(len(out['F']['events']), 4)
        access = access_trial(sp, b, sec, wit, agg, [1, 3], 2)
        self.assertEqual(len(access), 4)

    def test_invalid_y_rejected_before_commit(self):
        regs = []
        for i, (sec, pub) in enumerate(self.keys):
            reg, _ = p.generate_private(self.sp, self.issuer, sec, pub, self.bits[i])
            regs.append(reg)
        # A valid proof with an altered Y needs a fresh proof; instead confirm the
        # statement-binding rejection, and separately a deterministic Y failure.
        altered = dict(regs[0].Y)
        row = list(altered[1, 0]); row[0] = a.g2_prod([row[0], self.sp.g2]); altered[1, 0] = tuple(row)
        regs[0] = replace(regs[0], Y=altered)
        with self.assertRaises(c.ProtocolError):
            p.aggregate(self.sp, regs, self.receipts, {})
        from regabe.validation import _global_round
        self.assertFalse(_global_round(self.sp, regs, 'auto'))


if __name__ == '__main__':
    unittest.main()
