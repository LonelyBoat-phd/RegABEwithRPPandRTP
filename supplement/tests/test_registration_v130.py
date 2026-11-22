"""Regression tests for measurement boundaries and registration randomness."""
from dataclasses import fields, replace
import unittest
from unittest.mock import patch

from regabe import primitives as a
from regabe import core as c
from regabe.validation import individual_round_validated
from supplement import protocol as p
from supplement.run import fixture, make_recipe


class Registration130Tests(unittest.TestCase):
    def test_source_secret_has_no_registration_masks_and_reggen_is_fresh(self):
        sp, issuer = a.setup(2, 1)
        secret, pk = a.source_keygen(sp, 0)
        self.assertEqual([field.name for field in fields(secret)], ['slot', 'zeta'])
        receipt = a.validate_source(sp, pk)
        first = a.generate_registration(sp, issuer, 0, (0,), secret, pk, source_receipt=receipt)
        second = a.generate_registration(sp, issuer, 0, (0,), secret, pk, source_receipt=receipt)
        self.assertNotEqual(first.witness.xi, second.witness.xi)
        self.assertNotEqual(first.public.X, second.public.X)
        self.assertTrue(a.verify_registration(sp, first.public, source_receipt=receipt))
        self.assertTrue(a.verify_registration(sp, second.public, source_receipt=receipt))

    def test_full_source_validation_is_inside_each_measured_roster_pipeline(self):
        original_measure, original_valid = p.measure, a.source_key_valid
        active = [False]
        seen = []
        def measure(metrics, name, operation):
            if name != 'aggregate_total_s':
                return original_measure(metrics, name, operation)
            active[0] = True
            try:
                return original_measure(metrics, name, operation)
            finally:
                active[0] = False
        def valid(sp, pk):
            seen.append((active[0], pk.slot))
            return original_valid(sp, pk)
        with patch.object(p, 'measure', side_effect=measure), patch.object(a, 'source_key_valid', side_effect=valid):
            fixture(2, 1, 19)
        self.assertEqual(len(seen), 4)
        self.assertTrue(all(inside for inside, _ in seen))

    def test_cached_source_validation_is_auxiliary_and_separately_charged(self):
        details = {}
        with patch.object(a, 'source_key_valid', wraps=a.source_key_valid) as valid:
            fixture(2, 1, 19, source_validation='cached', details=details)
        self.assertEqual(valid.call_count, 2)
        self.assertGreater(details['preparation']['source_validation_prepare_s'], 0)

    def test_source_validation_uses_exact_native_batch_and_checks_relations(self):
        sp, _ = a.setup(2, 1)
        _, pk = a.source_keygen(sp, 0)
        with patch.object(a.GROUP, 'member_many', wraps=a.GROUP.member_many) as batch, \
             patch.object(a, 'pairing_equal', wraps=a.pairing_equal) as equation:
            self.assertTrue(a.source_key_valid(sp, pk))
            batch.assert_called_once_with((pk.T, pk.Q, *pk.V.values()))
            self.assertEqual(equation.call_count, sp.ctx.L)
        self.assertFalse(a.source_key_valid(sp, replace(pk, Q=a.FQ12.one())))
        self.assertFalse(a.source_key_valid(sp, replace(pk, Q=pk.Q * sp.g2)))
        self.assertFalse(a.source_key_valid(sp, replace(pk, V={})))

    def test_precompute_is_built_before_generation_and_leaf_times_do_not_overlap(self):
        original = a._registration_tables
        cache_was_present = []
        def tables(sp):
            cache_was_present.append(sp._registration_precompute is not None)
            return original(sp)
        details = {}
        with patch.object(a, '_registration_tables', side_effect=tables):
            *_, metrics = fixture(2, 1, 20, details=details)
        self.assertFalse(cache_was_present[0])
        self.assertTrue(all(cache_was_present[1:]))
        self.assertGreater(metrics['Private']['registration_precompute_s'], 0)
        for samples in details['generation_users'].values():
            for row in samples:
                self.assertGreaterEqual(row['unattributed_s'], 0)
                self.assertLessEqual(sum(row['stages'].values()), row['generation_s'])
        self.assertGreater(metrics['Private']['gen_Y_s'], 0)
        self.assertGreater(metrics['Private']['Y_weights_s'], 0)
        self.assertLessEqual(sum(metrics['Private'][key] for key in
                            ('Y_weights_s', 'Y_msm_s', 'Y_pairing_s')), metrics['Private']['Y_global_s'])

    def test_reference_has_same_checks_one_global_round_and_same_candidate(self):
        for reverse in (False, True):
            details = {}
            members = []
            private_checks = {}
            original = a.member_many
            original_aggregate = p.aggregate
            def member(points):
                points = tuple(points)
                members.append(len(points))
                return original(points)
            def aggregate(sp, records, receipts, metrics, *, y_verifier):
                start = len(members)
                result = original_aggregate(sp, records, receipts, metrics, y_verifier=y_verifier)
                if isinstance(records[0], p.PrivateRecord):
                    private_checks[y_verifier] = members[start:]
                return result
            with patch.object(p, '_global_round', wraps=p._global_round) as global_round, \
                 patch.object(a, 'source_key_valid', wraps=a.source_key_valid) as source, \
                 patch.object(p, 'aggregate', side_effect=aggregate), \
                 patch.object(a, 'member_many', side_effect=member):
                *_, aggregates, metrics = fixture(2, 1, 21, reverse, y_reference=True, details=details)
            self.assertEqual(global_round.call_count, 1)
            self.assertEqual(source.call_count, 6)  # public, global private, reference private
            self.assertEqual(private_checks['global'], private_checks['individual'])
            self.assertEqual(details['y_reference']['candidate_root'], aggregates['Private'][1].tree.root.hex())
            self.assertEqual(details['y_reference']['execution_order'][0], 'individual' if reverse else 'global')
            self.assertGreater(details['y_reference']['metrics']['Y_individual_s'], 0)

    def test_individual_reference_checks_every_relation_without_membership_recheck(self):
        sp, issuer = a.setup(2, 1)
        records = []
        for i in range(2):
            secret, pk = a.source_keygen(sp, i)
            record, _ = p.generate_private(sp, issuer, secret, pk, (0,))
            records.append(record)
        changed = dict(records[0].Y)
        changed[1, 0] = (changed[1, 0][0] * sp.g2,)
        records[0] = replace(records[0], Y=changed)
        with patch.object(a, 'pairing_equal', wraps=a.pairing_equal) as equation, \
             patch.object(a, 'member_g1', side_effect=AssertionError('duplicate membership')):
            self.assertFalse(individual_round_validated(sp, records))
        self.assertEqual(equation.call_count, 2)

    def test_global_failure_cannot_fall_back_to_reference(self):
        with patch.object(p, '_global_round', return_value=False), \
             patch.object(p, 'individual_round_validated', side_effect=AssertionError('fallback')):
            with self.assertRaises(c.ProtocolError):
                fixture(2, 1, 22, y_reference=True)

    def test_default_recipe_and_explicit_comparison_scope(self):
        recipe = make_recipe('formal')
        self.assertEqual(recipe['source_validation'], 'full')
        self.assertIsNone(recipe['access_config'])
        self.assertFalse(recipe['y_reference'])
        custom = make_recipe('smoke', registration_only=True, grid=[(2, 1)], y_reference=True)
        self.assertEqual(custom['grid'], [(2, 1)])
        self.assertEqual(custom['update_configs'], [])
        self.assertTrue(custom['y_reference'])
        selective = make_recipe('smoke', grid=[(3, 4)], update_grid=[(4, 4)],
                                y_reference_grid=[(2, 1)])
        self.assertEqual(selective['grid'], [(3, 4), (4, 4), (2, 1)])
        self.assertEqual(selective['y_reference_configs'], [(2, 1)])


if __name__ == '__main__':
    unittest.main()
