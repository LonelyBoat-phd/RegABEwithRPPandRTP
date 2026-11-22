"""Fixture-level update/history statistics and exact-byte component tables."""
from collections import defaultdict
import math
import statistics


def dynamic_report(out, manifest, fixtures):
    from .report import write_csv, summarize
    import matplotlib.pyplot as plt
    recipe = manifest['recipe']
    repeats = recipe['repeats']
    event_rows, byte_rows, history_rows, inner_rows, init_rows, prepare_rows = [], [], [], [], [], []
    def byte_scope(obj, scope, scheme, components, event=0, h=0, start=0):
        total = components.get('total_bytes')
        if total is None or sum(v for k, v in components.items() if k != 'total_bytes') != total:
            raise ValueError('byte component reduction mismatch')
        for component, value in components.items():
            if type(value) is not int or value < 0:
                raise ValueError('invalid byte observation')
            byte_rows.append({'scope': scope, 'L': obj['L'], 'u': obj['u'], 'scheme': scheme,
                'round': obj['round'], 'warmup': obj['warmup'], 'event_index': event,
                'H': h, 'from_version': start, 'component': component, 'bytes': value})
    for obj in fixtures:
        for scheme, parts in obj['registration_details']['upload_components'].items():
            byte_scope(obj, 'registration_roster', scheme, parts)
        for scheme, result in obj.get('updates', {}).items():
            for row in result['events']:
                for metric, value in row['metrics'].items():
                    event_rows.append({'L': obj['L'], 'u': obj['u'], 'scheme': scheme,
                        'round': obj['round'], 'warmup': obj['warmup'], 'event_index': row['event_index'],
                        'target': row['target'], 'attribute': row['attribute'], 'version': row['version'],
                        'metric': metric, 'seconds': value})
                for name, parts in [('publication', row['publication_components']), ('client_response', row['client_components'])]:
                    byte_scope(obj, name, scheme, parts, event=row['event_index'])
                if (row['publication_components']['total_bytes'] != row['publication_bytes']
                        or row['client_components']['total_bytes'] != row['client_fetch_bytes']):
                    raise ValueError('update byte total mismatch')
        history = obj.get('history')
        expected_history = any((obj['L'], obj['u']) == tuple(point)
                               for point in recipe['history_configs'])
        if expected_history and history is None:
            raise ValueError('missing requested history measurements')
        if history is None:
            continue
        start = recipe['checkpoint_events']
        if (set(history['schemes']) != {'R', 'F'} or history['observer'] != 0
                or history['checkpoint_events'] != start):
            raise ValueError('incomplete or mismatched history configurations')
        schedule = history['schedule']
        if (len(schedule) != start + max(recipe['history_lengths'])
                or len({(x['target'], x['attribute']) for x in schedule}) != len(schedule)
                or any(x['target'] == history['observer'] for x in schedule)):
            raise ValueError('invalid committed history schedule')
        for scheme, data in history['schemes'].items():
            for metric, value in data['initialization'].items():
                init_rows.append({'L': obj['L'], 'u': obj['u'], 'scheme': scheme,
                    'round': obj['round'], 'warmup': obj['warmup'], 'metric': metric, 'seconds': value})
            for metric, value in data['preparation'].items():
                prepare_rows.append({'L': obj['L'], 'u': obj['u'], 'scheme': scheme,
                    'round': obj['round'], 'warmup': obj['warmup'], 'metric': metric, 'seconds': value})
            rows = data['measurements']
            if [row['H'] for row in rows] != recipe['history_lengths']:
                raise ValueError('missing history lengths')
            for row in rows:
                h = row['H']
                if (row['from_version'] != start or row['to_version'] != start + h
                        or row['processed_events'] != h or row['state_check'] != 'passed'
                        or len(row['inner_samples']) != recipe['history_replays']):
                    raise ValueError('invalid history measurement boundary')
                base = {'L': obj['L'], 'u': obj['u'], 'scheme': scheme, 'H': h,
                        'from_version': start, 'round': obj['round'], 'warmup': obj['warmup']}
                for metric, value in row['metrics'].items():
                    actual = statistics.mean(sample[metric] for sample in row['inner_samples'])
                    if not math.isfinite(value) or value < 0 or not math.isclose(actual, value, rel_tol=1e-12, abs_tol=1e-12):
                        raise ValueError('history inner reduction mismatch')
                    history_rows.append({**base, 'metric': metric, 'unit': 'seconds', 'value': value})
                if row['response_bytes'] != row['response_components']['total_bytes']:
                    raise ValueError('history response size mismatch')
                history_rows.append({**base, 'metric': 'response_bytes', 'unit': 'bytes', 'value': row['response_bytes']})
                for index, sample in enumerate(row['inner_samples']):
                    for metric, value in sample.items():
                        inner_rows.append({**base, 'replay_index': index, 'metric': metric, 'seconds': value})
                byte_scope(obj, 'history_responses', scheme, row['response_components'], h=h, start=start)
    groups = defaultdict(list)
    indexed = {}
    for row in history_rows:
        if row['warmup']:
            continue
        key = tuple(row[k] for k in ('L', 'u', 'scheme', 'H', 'from_version', 'metric', 'unit'))
        groups[key].append(row['value'])
        indexed[key + (row['round'],)] = row['value']
    summary = []
    for key, values in sorted(groups.items()):
        if len(values) != repeats:
            raise ValueError('history fixture sample count mismatch')
        summary.append(dict(zip(('L', 'u', 'scheme', 'H', 'from_version', 'metric', 'unit'), key), **summarize(values)))
    paired = []
    for row in summary:
        if row['scheme'] != 'R':
            continue
        base = (row['L'], row['u'])
        keys = [(base + ('R', row['H'], row['from_version'], row['metric'], row['unit'], r),
                 base + ('F', row['H'], row['from_version'], row['metric'], row['unit'], r))
                for r in range(recipe['warmups'], recipe['warmups'] + repeats)]
        if not all(k in indexed and v in indexed for k, v in keys):
            continue
        differences = [indexed[v] - indexed[k] for k, v in keys]
        denominator = statistics.mean(indexed[k] for k, v in keys)
        ratio = statistics.mean(indexed[v] for k, v in keys) / denominator if denominator else ''
        paired.append({k: row[k] for k in ('L', 'u', 'H', 'from_version', 'metric', 'unit')} |
                      {'control': 'R', 'treatment': 'F', 'ratio_of_means': ratio, **summarize(differences)})
    # Byte event observations are reduced within fixture before any CI.
    within = defaultdict(list)
    for row in byte_rows:
        if not row['warmup']:
            key = tuple(row[k] for k in ('scope', 'L', 'u', 'scheme', 'H', 'from_version', 'component', 'round'))
            within[key].append(row['bytes'])
    byte_groups = defaultdict(list)
    for key, values in within.items():
        byte_groups[key[:-1]].append(statistics.mean(values))
    byte_summary = []
    for key, values in sorted(byte_groups.items()):
        if len(values) != repeats:
            raise ValueError('byte fixture sample count mismatch')
        byte_summary.append(dict(zip(('scope', 'L', 'u', 'scheme', 'H', 'from_version', 'component'), key),
                                 unit='bytes', **summarize(values)))
    for name, rows in [('update-event-samples.csv', event_rows), ('byte-components.csv', byte_rows),
                       ('byte-components-summary.csv', byte_summary), ('history-samples.csv', history_rows),
                       ('history-inner-samples.csv', inner_rows), ('history-summary.csv', summary),
                       ('history-paired-increments.csv', paired), ('history-initialization-samples.csv', init_rows),
                       ('history-preparation-samples.csv', prepare_rows)]:
        write_csv(out / name, rows)
    if summary:
        configs = sorted({(row['L'], row['u']) for row in summary})
        columns = min(3, len(configs))
        fig, axes = plt.subplots((len(configs) + columns - 1) // columns, columns,
                                 figsize=(4 * columns, 3.4 * ((len(configs) + columns - 1) // columns)),
                                 squeeze=False, constrained_layout=True)
        for ax, (L, u) in zip(axes.flat, configs):
            for scheme, color in [('R', '#C87941'), ('F', '#247C80')]:
                rows = sorted([row for row in summary if row['L'] == L and row['u'] == u
                               and row['scheme'] == scheme and row['metric'] == 'catchup_processing_s'], key=lambda row: row['H'])
                ax.errorbar([row['H'] for row in rows], [row['mean'] for row in rows],
                            yerr=[row['ci95_half'] for row in rows], marker='o', capsize=3, label=scheme, color=color)
            ax.set_title(f'Offline replay; L={L}, u={u}, s={recipe["checkpoint_events"]}')
            ax.set_xlabel('Committed events H'); ax.set_ylabel('Processing time (s)')
            ax.set_ylim(bottom=0); ax.legend(); ax.grid(alpha=.2)
        for ax in list(axes.flat)[len(configs):]:
            ax.set_visible(False)
        if recipe['profile'] == 'smoke':
            fig.suptitle('SMOKE VALIDATION ONLY — not paper results')
        for ext in ('png', 'pdf'):
            fig.savefig(out / 'figures' / f'history-catchup.{ext}', dpi=180)
        plt.close(fig)
    return {'history_series': len(summary), 'byte_series': len(byte_summary)}
