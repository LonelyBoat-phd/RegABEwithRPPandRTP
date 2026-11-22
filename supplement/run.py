"""Serial, checkpointed registration, revocation, and access evaluation."""
import argparse
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import sys
from time import perf_counter

from regabe import primitives as a, core as c
from regabe.policy import all_attributes_and
from bench import environment
from . import protocol as p
from .materials import registration_parts, update_parts, sum_parts
from .workloads import legal_schedule
from .history import history_trial
from regabe.metrics import account

VERSION = 'regabe-reference-1.3.2'
ROOT = Path(__file__).resolve().parent.parent
FORMAL_GRID = [(16, 32), (32, 32), (64, 32), (32, 64), (32, 128)]


def atomic_json(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n')
    os.replace(tmp, path)


def fingerprint():
    h = hashlib.sha256()
    paths = sorted((ROOT / 'regabe').glob('*.py')) + sorted((ROOT / 'supplement').glob('*.py'))
    paths += [ROOT / 'bench.py', ROOT / 'native/type1.c', ROOT / 'supplement/optimization-config.json']
    for path in paths:
        h.update(str(path.relative_to(ROOT)).encode() + b'\0' + path.read_bytes())
    return h.hexdigest()


def qualified_count(u, density=None):
    """Number of qualified attributes per non-observer user (bit 0)."""
    if density is None:
        return u // 2
    count = int(round(density * u))
    return max(0, min(u, count))


def profiles_for(L, u, seed, density=None):
    rng = random.Random(seed)  # public synthetic workload only, never crypto coins
    count = qualified_count(u, density)
    rows = [(0,) * u]         # monitored observer satisfies every selected policy
    for _ in range(1, L):
        available = set(rng.sample(range(u), count))
        rows.append(tuple(0 if w in available else 1 for w in range(u)))
    return tuple(rows)


def fixture(L, u, seed, reverse=False, *, source_validation='full',
            y_reference=False, details=None, density=None):
    if source_validation not in ('full', 'cached'):
        raise ValueError('source validation mode')
    details = {} if details is None else details
    profile = profiles_for(L, u, seed, density)
    sp, issuer = a.setup(L, u)  # common preparation; no source verification here
    keys = [a.source_keygen(sp, i) for i in range(L)]
    secrets_, public_keys = zip(*keys)
    preparation = {}
    receipts = None
    if source_validation == 'cached':
        receipts = p.measure(preparation, 'source_validation_prepare_s',
                             lambda: [a.validate_source(sp, pk) for pk in public_keys])
    metrics = {'P': {}, 'Private': {}}
    # One shared set of public fixed-base tables. This is an explicitly reported
    # initialization cost, not amortized into the mean user registration time.
    p.measure(metrics['Private'], 'registration_precompute_s', lambda: a._registration_tables(sp))
    details['source_validation'] = source_validation
    details['preparation'] = preparation
    details['generation_users'] = {}
    details['upload_components'] = {}
    records, witnesses, aggregates = {}, {}, {}
    for scheme in (('Private', 'P') if reverse else ('P', 'Private')):
        m = metrics[scheme]
        user_samples = []
        def generate_all():
            generated = []
            for slot, (sec, pk, bits) in enumerate(zip(secrets_, public_keys, profile)):
                leaves = {}
                start = perf_counter()
                value = (p.generate_public if scheme == 'P' else p.generate_private)(
                    sp, issuer, sec, pk, bits, metrics=leaves)
                elapsed = perf_counter() - start
                leaf_sum = sum(leaves.values())
                c.check(leaf_sum <= elapsed, 'generation leaf timers overlap')
                user_samples.append({'slot': slot, 'generation_s': elapsed,
                    'stages': leaves, 'unattributed_s': elapsed - leaf_sum})
                generated.append(value)
            return tuple(generated)
        values = p.measure(m, 'generation_total_s', generate_all)
        if scheme == 'P':
            records[scheme] = values
            witnesses[scheme] = tuple(a.RegistrationWitness(tuple(b), 0, (0,) * u) for b in profile)
        else:
            records[scheme], witnesses[scheme] = tuple(x[0] for x in values), tuple(x[1] for x in values)
        details['generation_users'][scheme] = user_samples
        m['generation_mean_user_s'] = sum(x['generation_s'] for x in user_samples) / L
        m['generation_dispatch_s'] = m['generation_total_s'] - sum(x['generation_s'] for x in user_samples)
        for sample in user_samples:
            for name, value in sample['stages'].items():
                m[name] = m.get(name, 0.0) + value
        m['generation_unattributed_s'] = sum(x['unattributed_s'] for x in user_samples)
        # No decoder is modeled. Encoding byte counts are collected before either
        # verifier so both see equally populated immutable-element byte caches.
        details['upload_components'][scheme] = sum_parts(registration_parts(sp, r) for r in records[scheme])
        m['upload_total_bytes'] = details['upload_components'][scheme]['total_bytes']
        m['upload_mean_user_bytes'] = m['upload_total_bytes'] / L
        variants = ['global']
        if scheme == 'Private' and y_reference:
            variants = ['individual', 'global'] if reverse else ['global', 'individual']
        for variant in variants:
            aggregate_metrics = {}
            total = {}
            candidate = p.measure(total, 'aggregate_total_s', lambda:
                p.aggregate(sp, records[scheme], receipts, aggregate_metrics, y_verifier=variant))
            parent_names = ('snapshot_s', 'record_verify_s', 'Y_membership_s',
                            'Y_global_s', 'Y_individual_s', 'products_s', 'authenticated_state_s')
            residual = total['aggregate_total_s'] - sum(aggregate_metrics.get(k, 0.0) for k in parent_names)
            c.check(residual >= 0, 'aggregate parent timers overlap')
            combined = {**total, **aggregate_metrics, 'aggregate_residual_s': residual}
            if variant == 'global':
                aggregates[scheme] = candidate
                m.update(combined)
            else:
                # Read-only deterministic reference: never installed in runtime,
                # never retries, overrides or replaces the global decision.
                details['y_reference'] = {'metrics': combined,
                    'execution_order': variants,
                    'relations': u * L * (L - 1),
                    'source_validation': source_validation,
                    'candidate_root': candidate[1].tree.root.hex(),
                    'role': 'read-only deterministic performance reference; not main admission'}
    if 'y_reference' in details:
        c.check(details['y_reference']['candidate_root'] == aggregates['Private'][1].tree.root.hex(),
                'reference/global aggregate roots differ')
    _, state_p, _ = aggregates['P']; _, state_r, _ = aggregates['Private']
    for w in (0, u - 1):
        mask = sum(x.xi[w] for x in witnesses['Private']) % a.P
        c.check(state_r.blocks[w].descriptor.U == a.g1_prod([state_p.blocks[w].descriptor.U, a.g1_pow(sp.g1, mask)]), 'aggregate invariant')
    return sp, profile, secrets_, witnesses, aggregates, metrics


def check_access(rt, K, private=True):
    _, kc, board, users = rt
    user = users[0]; policy = all_attributes_and(range(K), a.P)
    sender = kc.sender_input(board, policy.rho)
    message = kc.public.omega ** 123
    ct = c.encrypt(sender, policy, message, board.trust, latest=board.latest)
    labels = user.labels(policy)
    material = kc.decrypt_input(board, 0, labels, ct.head)
    c.check(user.decrypt(material, ct) == message, 'access correctness')


def update_trial(sp, profile, secrets_, witnesses, aggregates, seed, events, reverse=False):
    schedule = legal_schedule(profile, events, seed + 100000)
    results = {}
    for scheme in (('F', 'R') if reverse else ('R', 'F')):
        init = {}
        rt = p.runtime(sp, profile, aggregates['Private'], secrets_, witnesses['Private'], scheme, init)
        _, kc, board, users = rt
        totals = {}; public_bytes = []; fetch_bytes = []; event_records = []
        before_xi = tuple(users[0]._xi)
        truth = [list(row) for row in profile]
        for event_no, (target, attr) in enumerate(schedule):
            metric = {}
            packet, receipt = p.revoke(rt, target, attr, metric)
            material = p.measure(metric, 'fetch_local_s', lambda: kc.sync_input(0, receipt.head.digest))
            p.measure(metric, 'client_event_s', lambda: users[0].catch_up(material, metrics=metric))
            account(metric, 'client_event_s', ('client_',), 'client_unattributed_s')
            # A second user exercises targeted as well as unaffected transitions.
            users[1].catch_up(kc.sync_input(1, receipt.head.digest))
            truth[target][attr] = 1
            c.check(users[0].bits == tuple(truth[0]) and users[1].bits == tuple(truth[1]), 'private/public self-test bits')
            c.check(not users[0].catch_up(material), 'idempotent exact retry')
            publication_parts, client_parts = update_parts(packet, receipt, material)
            pub_size, own_size = publication_parts['total_bytes'], client_parts['total_bytes']
            public_bytes.append(pub_size); fetch_bytes.append(own_size)
            for name, value in metric.items():
                totals[name] = totals.get(name, 0.0) + value
            event_records.append({'event_index': event_no + 1, 'metrics': metric,
                                  'publication_bytes': pub_size, 'client_fetch_bytes': own_size,
                                  'target': target, 'attribute': attr, 'version': receipt.head.version,
                                  'publication_components': publication_parts, 'client_components': client_parts})
        if scheme == 'R':
            c.check(tuple(users[0]._xi) == before_xi, 'public target keeps initial masks')
        check_access(rt, min(4, sp.ctx.u))
        # A revoked qualification must fail for its target, independent of access timing.
        for target, attr in schedule:
            if target == 1:
                try:
                    users[1].labels(all_attributes_and([attr], a.P))
                except a.UnsatisfiedPolicy:
                    break
                raise AssertionError('revoked user still satisfies revoked attribute')
        mean = {name: value / events for name, value in totals.items()}
        mean['publication_bytes'] = sum(public_bytes) / events
        mean['client_fetch_bytes'] = sum(fetch_bytes) / events
        results[scheme] = {'mean_per_event': mean, 'events': event_records, 'initialization': init}
    return results


def access_trial(sp, profile, secrets_, witnesses, aggregates, ks, repeats, reverse=False):
    results = {}
    for scheme in (('F', 'P') if reverse else ('P', 'F')):
        group = 'P' if scheme == 'P' else 'Private'
        rt = p.runtime(sp, profile, aggregates[group], secrets_, witnesses[group], scheme, slots=(0,))
        _, kc, board, users = rt
        user = users[0]
        for K in ks:
            policy = all_attributes_and(range(K), a.P); message = kc.public.omega ** 123
            sender = kc.sender_input(board, policy.rho)
            labels = user.labels(policy)  # cached reconstruction, excluded
            material = kc.decrypt_input(board, 0, labels, user.head)
            # One local access warmup per policy, not part of recorded inner samples.
            ct = c.encrypt(sender, policy, message, board.trust, latest=board.latest)
            c.check(user.decrypt(material, ct) == message, 'access warmup')
            inner = []
            for _ in range(repeats):
                m = {}
                ct = p.measure(m, 'Encrypt_s', lambda: c.encrypt(sender, policy, message, board.trust, latest=board.latest))
                got = p.measure(m, 'Decrypt_warm_s', lambda: user.decrypt(material, ct))
                c.check(got == message, 'access sample')
                inner.append(m)
            results[f'{scheme}:{K}'] = {'scheme': scheme, 'K': K, 'inner_samples': inner,
                                       'mean_per_fixture': {name: sum(r[name] for r in inner) / len(inner) for name in inner[0]}}
    return results


def make_recipe(profile, skip_access=True, *, source_validation='full', y_reference=False,
                y_reference_grid=None,
                registration_only=False, grid=None, update_grid=None, update_events=None,
                history_lengths=None, history_grid=None, checkpoint_events=0, history_replays=1,
                warmups=None, repeats=None, seed_base=None, density=None):
    smoke = profile == 'smoke'
    base_grid = list(grid) if grid is not None else ([(3, 4)] if smoke else list(FORMAL_GRID))
    lengths = sorted(history_lengths or [])
    event_count = (4 if smoke else 16) if update_events is None else update_events
    # Explicit warm-up / measured-fixture counts override the profile defaults so a
    # fixed recipe (formal: 10 warm-ups + 50 measured fixtures) is recorded in the
    # manifest and therefore enforced by resume.
    warmup_count = (1 if smoke else 10) if warmups is None else warmups
    repeat_count = (2 if smoke else 50) if repeats is None else repeats
    if type(warmup_count) is not int or warmup_count < 0:
        raise ValueError('invalid warm-up count')
    if type(repeat_count) is not int or repeat_count < 2:
        raise ValueError('measured repeats must be an integer >= 2 for confidence intervals')
    if density is not None and (not isinstance(density, float) or not 0.0 < density <= 1.0):
        raise ValueError('density must be a float in (0, 1]')
    if registration_only and (update_grid is not None or lengths or history_grid is not None):
        raise ValueError('--registration-only cannot enable updates/history')
    if (type(event_count) is not int or event_count < 1 or type(checkpoint_events) is not int
            or checkpoint_events < 0 or type(history_replays) is not int or history_replays < 1
            or len(lengths) != len(set(lengths)) or any(type(h) is not int or h < 1 for h in lengths)):
        raise ValueError('invalid update/history dimensions')
    if history_grid is not None and not lengths:
        raise ValueError('--history-grid requires --history-lengths')
    defaults = [(3, 4)] if smoke else [(16, 32), (32, 32), (64, 32)]
    updates = [] if registration_only else (list(update_grid) if update_grid is not None
                else [point for point in base_grid if tuple(point) in defaults])
    histories = (list(history_grid) if history_grid is not None else (updates or base_grid)) if lengths else []
    explicit_reference = list(y_reference_grid) if y_reference_grid is not None else []
    effective = list(dict.fromkeys(tuple(point) for point in base_grid + updates + histories + explicit_reference))
    reference_configs = explicit_reference if y_reference_grid is not None else (effective if y_reference else [])
    if not effective or any(len(point) != 2 or point[0] < 2 or point[1] < 1 for point in effective):
        raise ValueError('invalid parameter grid')
    for L, u in updates:
        if event_count > (L - 1) * qualified_count(u, density):
            raise ValueError(f'update count exceeds legal workload capacity at {(L, u)}')
    for L, u in histories:
        if checkpoint_events + max(lengths) > (L - 1) * qualified_count(u, density):
            raise ValueError(f'checkpoint plus history exceeds legal workload capacity at {(L, u)}')
    return {'version': VERSION, 'profile': profile,
            'grid': effective,
            'warmups': warmup_count, 'repeats': repeat_count,
            'update_events': event_count,
            'update_configs': updates,
            'history_configs': histories, 'history_lengths': lengths,
            'checkpoint_events': checkpoint_events, 'history_replays': history_replays,
            'update_timing': 'object-level proposal/validation/client parents with disjoint leaf stages; initialization and material preparation separate',
            'history_timing': 'restore outside timer; H contiguous committed events from checkpoint; no fetching, decoding or checkpoint creation in replay timer',
            'history_statistics': 'fixture independent; replay repetitions averaged within fixture; H prefixes correlated',
            'byte_accounting': 'actual encoders; disjoint components plus framing; repeated heads/signatures counted; no network headers',
            'access_config': None if skip_access else ((3, 4) if smoke else (32, 128)),
            'access_K': [1, 3] if smoke else [16, 64], 'access_inner_repeats': 2 if smoke else 5,
            'qualification_density': density,
            'qualification_rule': ('observer 0 all available; every other user exactly '
                                   f'floor(u/2) qualified' if density is None else
                                   'observer 0 all available; every other user exactly '
                                   f'round(density*u) qualified (density={density})'),
            'qualification_workload': 'observer 0 all available; every other user the same fixed number of randomly selected available attributes',
            'workload_seed_base': 20261108 if seed_base is None else seed_base, 'source_sha256': fingerprint(),
            'optimization': __import__('supplement.optimization', fromlist=['options']).options(),
            'source_validation': source_validation,
            'source_validation_boundary': ('complete source checks inside roster admission' if source_validation == 'full'
                else 'auxiliary cached mode: full validation preparation separately recorded, bound receipt checks inside'),
            'registration_precomputation': 'shared public fixed-base tables built once per fixture; separately charged to initialization',
            'registration_input': 'pre-existing in-memory objects; no wire decoding or network transport',
            'registration_generation': 'local record construction including fresh masks, proof and signing; no ACA review service; encoding bytes separately counted',
            'registration_timing_units': 'generation_total_s and gen_*: roster; generation_mean_user_s: mean of measured individual calls',
            'y_reference': bool(reference_configs),
            'y_reference_configs': reference_configs,
            'y_reference_scope': 'read-only deterministic full pipeline on same records and same checks; not installed; alternating order',
            'fixture_checks': 'registration invariants and enabled workload checks; generic P/R/F access probes run in the test suite',
            'private_admission': 'one compact proof verification per record and one global randomized Y pass; no RA Y pass',
            'record_format': 'REGSIGMA26 compact linked proof shared by the package and experiment',
            'statistics_unit': 'independent fixture; event/access inner samples averaged within fixture',
            'publication_bytes': 'encoded proposal plus encoded commit receipt, counted as two published objects, including repeated head bytes',
            'client_bytes': 'standalone encoded sync response including signatures; no network or transport headers',
            'excluded': ['group parameter generation', 'common Setup', 'common SourceKeyGen',
                         'registration precomputation (reported separately)', 'wire decoding', 'ACA evidence/opening review service',
                         'human evidence review', 'network delivery latency', 'commit installation', 'material acquisition']}


def run(profile, output, skip_access=True, *, source_validation='full', y_reference=False,
        y_reference_grid=None,
        registration_only=False, grid=None, update_grid=None, update_events=None,
        history_lengths=None, history_grid=None, checkpoint_events=0, history_replays=1,
        warmups=None, repeats=None, seed_base=None, density=None):
    out = Path(output); out.mkdir(parents=True, exist_ok=True)
    recipe = make_recipe(profile, skip_access, source_validation=source_validation,
                         y_reference=y_reference, y_reference_grid=y_reference_grid,
                         registration_only=registration_only, grid=grid,
                         update_grid=update_grid, update_events=update_events,
                         history_lengths=history_lengths, history_grid=history_grid,
                         checkpoint_events=checkpoint_events, history_replays=history_replays,
                         warmups=warmups, repeats=repeats, seed_base=seed_base, density=density)
    env = environment()
    env['supplement_source_sha256'] = recipe['source_sha256']
    env['processor'] = platform.processor()
    manifest = {'recipe': recipe, 'environment': env}
    # JSON-normalize tuples before the resume comparison.
    manifest = json.loads(json.dumps(manifest))
    mf = out / 'manifest.json'
    if mf.exists():
        if json.loads(mf.read_text()) != manifest:
            raise SystemExit('Output belongs to different code/parameters/environment/recipe. Use a NEW --output directory.')
    else:
        atomic_json(mf, manifest)
    expected = []
    expected_total = len(recipe['grid']) * (recipe['warmups'] + recipe['repeats'])
    start = perf_counter()
    for L, u in recipe['grid']:
        for round_no in range(recipe['warmups'] + recipe['repeats']):
            warmup = round_no < recipe['warmups']
            key = f'L{L}-u{u}-r{round_no:02d}'
            path = out / 'rounds' / (key + '.json')
            expected.append(str(path.relative_to(out)))
            if path.exists():
                old = json.loads(path.read_text())
                if old.get('status') != 'passed' or old.get('source_sha256') != recipe['source_sha256']:
                    raise RuntimeError('invalid checkpoint: ' + str(path))
                print('[resume] ' + key, flush=True)
                continue
            print(f'[start] {key} warmup={warmup}', flush=True)
            seed = recipe['workload_seed_base'] + L * 100000 + u * 100 + round_no
            registration_details = {}
            sp, b, sec, wit, agg, registration = fixture(L, u, seed, bool(round_no % 2),
                source_validation=source_validation,
                y_reference=[L, u] in manifest['recipe']['y_reference_configs'],
                details=registration_details, density=density)
            result = {'status': 'passed', 'source_sha256': recipe['source_sha256'],
                      'L': L, 'u': u, 'round': round_no, 'warmup': warmup,
                      'workload_seed': seed, 'registration': registration, 'registration_details': registration_details}
            if [L, u] in manifest['recipe']['update_configs']:
                print(f'[updates] {key}', flush=True)
                result['updates'] = update_trial(sp, b, sec, wit, agg, seed, recipe['update_events'], bool(round_no % 2))
            if [L, u] == manifest['recipe']['access_config']:
                print(f'[access] {key}', flush=True)
                result['access'] = access_trial(sp, b, sec, wit, agg, recipe['access_K'], recipe['access_inner_repeats'], bool(round_no % 2))
            if [L, u] in manifest['recipe']['history_configs']:
                print(f'[history] {key}', flush=True)
                result['history'] = history_trial(sp, b, sec, wit, agg, seed,
                    recipe['history_lengths'], checkpoint_events=checkpoint_events,
                    replays=history_replays, reverse=bool(round_no % 2))
            atomic_json(path, result)
            atomic_json(out / 'execution-status.json', {'status': 'running', 'last_completed': key,
                        'completed': sum((out / q).exists() for q in expected),
                        'expected_total': expected_total,
                        'elapsed_this_invocation_s': perf_counter() - start})
            print('[done] ' + key, flush=True)
    atomic_json(out / 'execution-status.json', {'status': 'measurements_complete', 'expected_checkpoints': expected,
                'completed': len(expected), 'formal_results': profile == 'formal',
                'elapsed_this_invocation_s': perf_counter() - start})
    from .report import report
    report(out)


def cli():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=['formal', 'smoke'], default='formal')
    parser.add_argument('--output')
    parser.add_argument('--warmups', type=int,
                        help='discarded fixtures per point; overrides the profile default')
    parser.add_argument('--repeats', type=int,
                        help='measured independent fixtures per point (>=2); overrides the profile default')
    parser.add_argument('--seed-base', type=int, dest='seed_base',
                        help='workload seed base; a different value draws different fixtures')
    parser.add_argument('--density', type=float,
                        help='qualification density q in (0,1]: fraction of attributes each non-observer user holds; default floor(u/2)')
    access = parser.add_mutually_exclusive_group()
    access.add_argument('--include-access', action='store_true', help='legacy optional access timing; excluded by default')
    access.add_argument('--skip-access', action='store_true', help='compatibility flag; access is already excluded by default')
    parser.add_argument('--source-validation', choices=['full', 'cached'], default='full',
                        help='cached is an auxiliary diagnostic with separately recorded preparation cost')
    reference = parser.add_mutually_exclusive_group()
    reference.add_argument('--y-reference', action='store_true',
                           help='measure the deterministic Y reference at every fixture point')
    reference.add_argument('--y-reference-grid', nargs='+', metavar='L:u',
                           help='measure the deterministic Y reference only at these points; unioned with fixture grid')
    parser.add_argument('--registration-only', action='store_true')
    parser.add_argument('--grid', nargs='+', metavar='L:u', help='explicit registration points, e.g. 3:4 4:4')
    parser.add_argument('--update-grid', nargs='+', metavar='L:u', help='explicit update points; unioned with fixture grid')
    parser.add_argument('--update-events', type=int, help='distinct legal updates per fixture')
    parser.add_argument('--history-grid', nargs='+', metavar='L:u', help='explicit history points; requires history lengths')
    parser.add_argument('--history-lengths', type=int, nargs='+', metavar='H', help='enable offline replay for these committed history lengths')
    parser.add_argument('--checkpoint-events', type=int, default=0, help='committed prefix before offline checkpoint')
    parser.add_argument('--history-replays', type=int, default=1, help='inner repeats restored from same checkpoint; averaged within fixture')
    args = parser.parse_args()
    def parse_grid(values, option):
        if values is None:
            return None
        try:
            points = [tuple(map(int, item.split(':'))) for item in values]
            if any(len(point) != 2 or point[0] < 2 or point[1] < 1 for point in points) or len(set(points)) != len(points):
                raise ValueError()
            return points
        except ValueError:
            parser.error(option + ' requires distinct L:u pairs with L>=2 and u>=1')
    grid = parse_grid(args.grid, '--grid')
    y_reference_grid = parse_grid(args.y_reference_grid, '--y-reference-grid')
    update_grid = parse_grid(args.update_grid, '--update-grid')
    history_grid = parse_grid(args.history_grid, '--history-grid')
    output = args.output or ('results/supplement' if args.profile == 'formal' else 'results/supplement-smoke')
    try:
        run(args.profile, output, not args.include_access, source_validation=args.source_validation,
            y_reference=args.y_reference, y_reference_grid=y_reference_grid,
            registration_only=args.registration_only, grid=grid,
            update_grid=update_grid, update_events=args.update_events,
            history_lengths=args.history_lengths, history_grid=history_grid,
            checkpoint_events=args.checkpoint_events, history_replays=args.history_replays,
            warmups=args.warmups, repeats=args.repeats, seed_base=args.seed_base,
            density=args.density)
    except Exception as exc:
        atomic_json(Path(output) / 'last-error.json', {'status': 'failed', 'error_type': type(exc).__name__, 'message': str(exc)})
        raise


if __name__ == '__main__':
    cli()






