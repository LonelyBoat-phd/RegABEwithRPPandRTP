"""Multi-event replay, timing-boundary and exact-byte regression checks."""
from dataclasses import replace
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from regabe import primitives as a, core as c
from regabe.metrics import account
from supplement import protocol as p
from supplement.history import history_trial, same_state
from supplement.materials import registration_parts, update_parts, sum_parts
from supplement.run import fixture, update_trial, make_recipe
from supplement.workloads import legal_schedule


class Dynamic131Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sp, cls.profile, cls.secrets, cls.witnesses, cls.aggregates, _ = fixture(3, 4, 31)

    def runtime(self, scheme='F'):
        return p.runtime(self.sp, self.profile, self.aggregates['Private'], self.secrets,
                         self.witnesses['Private'], scheme)

    def test_update_stages_account_for_all_parent_time(self):
        result = update_trial(self.sp, self.profile, self.secrets, self.witnesses,
                              self.aggregates, 32, 3)
        for scheme, data in result.items():
            self.assertNotIn('authority_initialize_s', data['mean_per_event'])
            self.assertGreater(data['initialization']['authority_initialize_s'], 0)
            for row in data['events']:
                metric = row['metrics']
                for parent, prefixes, residual in [
                    ('revoke_prepare_s', ('ra_', 'proposal_'), 'revoke_unattributed_s'),
                    ('update_validate_s', ('kc_',), 'update_unattributed_s'),
                    ('client_event_s', ('client_',), 'client_unattributed_s')]:
                    expected = sum(value for name, value in metric.items()
                                   if name not in (parent, residual) and name.startswith(prefixes)) + metric[residual]
                    self.assertAlmostEqual(expected, metric[parent], places=12)
                if scheme == 'F':
                    self.assertGreater(metric['ra_prf_s'], 0)
                    self.assertGreater(metric['kc_membership_s'], 0)
                    self.assertGreater(metric['client_selftest_s'], 0)
                else:
                    self.assertNotIn('ra_prf_s', metric)
                    self.assertNotIn('client_selftest_s', metric)

    def test_timing_does_not_change_client_state_or_replay_behavior(self):
        for scheme in ('R', 'F'):
            rt = self.runtime(scheme)
            _, kc, _, users = rt
            left, right = users[0].checkpoint(), users[0].checkpoint()
            target, attr = legal_schedule(self.profile, 1, 33)[0]
            _, receipt = p.revoke(rt, target, attr, {})
            material = kc.sync_input(0, receipt.head.digest)
            self.assertTrue(left.catch_up(material))
            metric = {}
            self.assertTrue(right.catch_up(material, metrics=metric))
            self.assertTrue(same_state(left, right))
            self.assertFalse(right.catch_up(material, metrics={}))

    def test_instrumented_full_paths_retain_membership_and_signature_checks(self):
        rt = self.runtime('F')
        ra, kc, board, users = rt
        target, attr = legal_schedule(self.profile, 1, 34)[0]
        packet = kc.prepare_with(ra, target, attr)
        with patch.object(a.GROUP, 'member_many', wraps=a.GROUP.member_many) as batch:
            prepared = kc.validate(packet, metrics={})
        batch.assert_called_once_with((packet.du, *packet.dw))
        receipt = kc.commit(board, prepared); ra.accept_commit(receipt, board.trust)
        material = kc.sync_input(0, receipt.head.digest)
        with patch.object(c, 'verify', wraps=c.verify) as verify, \
             patch.object(c, 'verify_path', wraps=c.verify_path) as paths:
            users[0].catch_up(material, metrics={})
        self.assertEqual(verify.call_count, 3)
        self.assertEqual(paths.call_count, 2)

    def test_instrumented_tampering_rejects_without_client_installation(self):
        rt = self.runtime('F')
        _, kc, _, users = rt
        target, attr = legal_schedule(self.profile, 1, 35)[0]
        _, receipt = p.revoke(rt, target, attr, {})
        material = kc.sync_input(0, receipt.head.digest)
        before = users[0].checkpoint()
        bad = replace(material, own_delta=material.own_delta * self.sp.g1)
        with self.assertRaises(c.ProtocolError):
            users[0].catch_up(bad, metrics={})
        self.assertTrue(same_state(users[0], before))

    def test_registration_and_update_byte_components_match_actual_encoders(self):
        sp, issuer = a.setup(2, 1); secret, pk = a.source_keygen(sp, 0)
        public = p.generate_public(sp, issuer, secret, pk, (0,))
        private, _ = p.generate_private(sp, issuer, secret, pk, (0,))
        for record in (public, private):
            parts = registration_parts(sp, record)
            self.assertEqual(parts['total_bytes'], len(record.wire(sp)))
            self.assertEqual(sum(v for k, v in parts.items() if k != 'total_bytes'), parts['total_bytes'])
        for scheme in ('R', 'F'):
            rt = self.runtime(scheme)
            _, kc, _, _ = rt
            target, attr = legal_schedule(self.profile, 1, 36)[0]
            packet, receipt = p.revoke(rt, target, attr, {})
            material = kc.sync_input(0, receipt.head.digest)
            publication, response = update_parts(packet, receipt, material)
            self.assertEqual(publication['total_bytes'], len(c.seq([packet.canonical(), p.receipt_wire(receipt)])))
            self.assertEqual(response['total_bytes'], len(p.full_sync_wire(material) if scheme == 'F' else material.wire()))
            self.assertEqual(publication['head_bytes'], 2 * len(receipt.head.wire()))
            self.assertEqual(publication['signature_bytes'], 4 * 64)
            for row in (publication, response):
                self.assertEqual(sum(v for k, v in row.items() if k != 'total_bytes'), row['total_bytes'])
            self.assertEqual(sum_parts([response, response])['total_bytes'], 2 * response['total_bytes'])

    def test_offline_history_uses_midchain_checkpoint_and_matched_schedule(self):
        seen = {'R': [], 'F': []}
        original = p.revoke
        def revoke(rt, target, attr, metric):
            scheme = 'F' if isinstance(rt[0], c.RA) else 'R'
            seen[scheme].append((target, attr))
            return original(rt, target, attr, metric)
        with patch.object(p, 'revoke', side_effect=revoke):
            result = history_trial(self.sp, self.profile, self.secrets, self.witnesses,
                                   self.aggregates, 37, [1, 3], checkpoint_events=1, replays=2)
        self.assertEqual(seen['R'], seen['F'])
        self.assertEqual(len(seen['R']), 4)
        self.assertEqual(len(set(seen['R'])), 4)
        self.assertTrue(all(target != 0 for target, _ in seen['R']))
        for scheme, data in result['schemes'].items():
            for row in data['measurements']:
                self.assertEqual(row['from_version'], 1)
                self.assertEqual(row['to_version'], row['H'] + 1)
                self.assertEqual(row['processed_events'], row['H'])
                self.assertEqual(row['state_check'], 'passed')
                self.assertEqual(len(row['inner_samples']), 2)
                self.assertGreater(row['metrics']['catchup_processing_s'], 0)

    def test_replay_repetitions_restore_the_checkpoint(self):
        original = c.User.catch_up
        states = []
        def observe(user, material, *, metrics=None):
            if metrics is not None:
                states.append((user, user.version))
            return original(user, material, metrics=metrics)
        with patch.object(c.User, 'catch_up', observe):
            history_trial(self.sp, self.profile, self.secrets, self.witnesses,
                          self.aggregates, 38, [1, 3], checkpoint_events=1, replays=2)
        groups = {}
        for user, version in states:
            groups.setdefault(id(user), []).append(version)
        self.assertEqual(sorted(groups.values()), [[1], [1], [1, 2, 3], [1, 2, 3]])

    def test_history_capacity_and_invalid_lengths_fail_before_runtime(self):
        for lengths, prefix in [([5], 0), ([1, 1], 0), ([0], 0), ([3], 2)]:
            with patch.object(p, 'runtime', side_effect=AssertionError('runtime before validation')):
                with self.assertRaises(ValueError):
                    history_trial(self.sp, self.profile, self.secrets, self.witnesses,
                                  self.aggregates, 39, lengths, checkpoint_events=prefix)

    def test_partitioned_replay_and_missing_parent(self):
        rt = self.runtime('F'); _, kc, _, users = rt
        materials = []
        for target, attr in legal_schedule(self.profile, 3, 40):
            _, receipt = p.revoke(rt, target, attr, {})
            materials.append(kc.sync_input(0, receipt.head.digest))
        first, second = users[0].checkpoint(), users[0].checkpoint()
        for material in materials:
            first.catch_up(material)
        second.catch_up(materials[0])
        for material in materials[1:]:
            second.catch_up(material)
        self.assertTrue(same_state(first, second))
        before = users[0].checkpoint()
        with self.assertRaises(c.ProtocolError):
            users[0].catch_up(materials[1], metrics={})
        self.assertTrue(same_state(before, users[0]))

    def test_recipe_unions_explicit_stage_grids_and_checks_feasibility(self):
        recipe = make_recipe('smoke', grid=[(3, 4)], update_grid=[(3, 4), (3, 8), (4, 4)],
                             history_grid=[(3, 4)], history_lengths=[1, 3], checkpoint_events=1)
        self.assertEqual(recipe['grid'], [(3, 4), (3, 8), (4, 4)])
        self.assertEqual(recipe['history_lengths'], [1, 3])
        for kwargs in [dict(history_grid=[(3, 4)]), dict(history_lengths=[5]),
                       dict(update_grid=[(2, 1)]), dict(registration_only=True, history_lengths=[1])]:
            with self.assertRaises(ValueError):
                make_recipe('smoke', **kwargs)

    def test_formal_history_256_has_a_legal_schedule(self):
        from supplement.run import profiles_for
        lengths = [1, 8, 32, 128, 256]
        recipe = make_recipe('formal', grid=[(32, 32)], history_lengths=lengths,
                             checkpoint_events=8)
        self.assertEqual(recipe['history_lengths'], lengths)
        events = recipe['checkpoint_events'] + max(lengths)
        profiles = profiles_for(32, 32, 41)
        schedule = legal_schedule(profiles, events, 42)
        self.assertEqual(len(set(schedule)), events)
        self.assertTrue(all(i != 0 and profiles[i][w] == 0 for i, w in schedule))
        limit = (32 - 1) * (32 // 2) - recipe['checkpoint_events']
        at_limit = make_recipe('formal', grid=[(32, 32)], history_lengths=[limit], checkpoint_events=8)
        self.assertEqual(at_limit['history_lengths'], [limit])
        with self.assertRaisesRegex(ValueError, 'legal workload capacity'):
            make_recipe('formal', grid=[(32, 32)], history_lengths=[limit + 1], checkpoint_events=8)

    def test_report_rejects_missing_history_or_missing_control(self):
        from supplement.dynamic_report import dynamic_report
        recipe = make_recipe('smoke', history_lengths=[1])
        # No real measurements are fabricated: these incomplete records must fail
        # before a summary can be produced.
        obj = {'L': 3, 'u': 4, 'round': 1, 'warmup': False,
               'registration_details': {'upload_components': {}}}
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'missing requested history'):
                dynamic_report(Path(directory), {'recipe': recipe}, [obj])
            obj['history'] = {'observer': 0, 'checkpoint_events': 0, 'schemes': {'R': {}}}
            with self.assertRaisesRegex(ValueError, 'incomplete or mismatched'):
                dynamic_report(Path(directory), {'recipe': recipe}, [obj])


if __name__ == '__main__':
    unittest.main()
