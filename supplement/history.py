"""Offline replay of contiguous committed history on prebuilt memory objects."""
from time import perf_counter

from regabe import core as c
from regabe.metrics import account
from . import protocol as p
from .materials import response_parts, sum_parts
from .workloads import legal_schedule


def same_state(left, right):
    return all(getattr(left, name) == getattr(right, name) for name in
               ('head', 'version', '_bits', '_xi', '_counters', '_receipts'))


def history_trial(sp, profile, secrets_, witnesses, aggregates, seed, lengths,
                  *, checkpoint_events=0, replays=1, reverse=False, observer=0):
    lengths = list(lengths)
    if (not lengths or any(type(h) is not int or h < 1 for h in lengths)
            or len(set(lengths)) != len(lengths) or type(checkpoint_events) is not int
            or checkpoint_events < 0 or type(replays) is not int or replays < 1):
        raise ValueError('invalid history recipe')
    lengths = sorted(lengths)
    schedule = legal_schedule(profile, checkpoint_events + max(lengths), seed + 200000, observer)
    results = {}
    for scheme in (('F', 'R') if reverse else ('R', 'F')):
        init = {}
        rt = p.runtime(sp, profile, aggregates['Private'], secrets_, witnesses['Private'],
                       scheme, init, slots=(observer,))
        _, kc, _, users = rt
        preparation = {}
        online = users[observer]
        for target, attr in schedule[:checkpoint_events]:
            _, receipt = p.measure(preparation, 'history_generation_s', lambda: p.revoke(rt, target, attr, {}))
            material = p.measure(preparation, 'history_material_prepare_s', lambda: kc.sync_input(observer, receipt.head.digest))
            p.measure(preparation, 'history_reference_processing_s', lambda: online.catch_up(material))
        checkpoint = p.measure(preparation, 'offline_checkpoint_create_s', online.checkpoint)
        materials, byte_parts, expected = [], [], {}
        # This online reference advances normally while the offline checkpoint
        # remains untouched. No generation/fetch/checkpoint work enters replay time.
        for index, (target, attr) in enumerate(schedule[checkpoint_events:], 1):
            _, receipt = p.measure(preparation, 'history_generation_s', lambda: p.revoke(rt, target, attr, {}))
            material = p.measure(preparation, 'history_material_prepare_s', lambda: kc.sync_input(observer, receipt.head.digest))
            response = p.measure(preparation, 'history_encoding_accounting_s', lambda: response_parts(material))
            materials.append(material); byte_parts.append(response)
            c.check(p.measure(preparation, 'history_reference_processing_s', lambda: online.catch_up(material)), 'online reference did not advance')
            if index in lengths:
                expected[index] = p.measure(preparation, 'reference_checkpoint_s', online.checkpoint)
        measurements = []
        for h in lengths:
            inner = []
            # Slice construction and restoring private state are outside timers.
            selected = tuple(materials[:h])
            for _ in range(replays):
                offline = p.measure(preparation, 'offline_restore_s', checkpoint.checkpoint)
                metric = {}
                start = perf_counter()
                for material in selected:
                    if not offline.catch_up(material, metrics=metric):
                        raise c.ProtocolError('duplicate in committed replay history')
                metric['catchup_processing_s'] = perf_counter() - start
                account(metric, 'catchup_processing_s', ('client_',), 'catchup_unattributed_s')
                c.check(same_state(offline, expected[h]), 'offline/online state mismatch')
                c.check(offline.bits == checkpoint.bits, 'observer was targeted')
                inner.append(metric)
            components = sum_parts(byte_parts[:h])
            measurements.append({'H': h, 'from_version': checkpoint.version,
                'to_version': expected[h].version, 'processed_events': h,
                'inner_samples': inner,
                'metrics': {key: sum(sample[key] for sample in inner) / replays for key in inner[0]},
                'response_components': components, 'response_bytes': components['total_bytes'],
                'state_check': 'passed'})
        c.check(checkpoint.version == checkpoint_events, 'offline checkpoint was mutated')
        results[scheme] = {'initialization': init, 'preparation': preparation, 'measurements': measurements}
    return {'observer': observer, 'checkpoint_events': checkpoint_events,
            'schedule': [{'target': i, 'attribute': w} for i, w in schedule],
            'scope': 'committed events only; prebuilt encoded-cache-populated memory objects; no acquisition or decoding',
            'schemes': results}
