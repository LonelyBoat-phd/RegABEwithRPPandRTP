"""Recompute summaries and paired differences from checkpoint samples."""
import argparse
from collections import defaultdict
import csv
import json
import math
from pathlib import Path
import statistics

from scipy.stats import t
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


def write_csv(path, rows):
    if not rows:
        return
    with path.open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)


def summarize(values):
    n = len(values)
    mean = statistics.mean(values)
    sd = statistics.stdev(values) if n > 1 else 0.0
    half = float(t.ppf(.975, n - 1) * sd / math.sqrt(n)) if n > 1 else 0.0
    return {'n': n, 'mean': mean, 'sample_sd': sd, 'ci95_half': half,
            'ci95_low': mean - half, 'ci95_high': mean + half,
            'min': min(values), 'max': max(values)}


def report(out):
    out = Path(out)
    manifest = json.loads((out / 'manifest.json').read_text())
    recipe = manifest['recipe']
    records = []
    user_records = []
    fixtures = []
    for L, u in recipe['grid']:
        for r in range(recipe['warmups'] + recipe['repeats']):
            path = out / 'rounds' / f'L{L}-u{u}-r{r:02d}.json'
            obj = json.loads(path.read_text())
            if obj['status'] != 'passed' or obj['source_sha256'] != recipe['source_sha256']:
                raise ValueError('invalid checkpoint')
            fixtures.append(obj)
            if obj['warmup'] is not (r < recipe['warmups']):
                raise ValueError('checkpoint warm-up flag does not match the recipe')
            def add(stage, scheme, metric, value, K=0):
                if not isinstance(value, (float, int)) or not math.isfinite(value) or value < 0:
                    raise ValueError('invalid nonnegative observation')
                records.append({'stage': stage, 'L': L, 'u': u, 'scheme': scheme,
                                'K': K, 'round': r, 'warmup': obj['warmup'], 'metric': metric,
                                'unit': 'bytes' if metric.endswith('bytes') else 'seconds', 'value': value})
            for scheme, metrics in obj['registration'].items():
                for name, value in metrics.items():
                    add('initialization' if name == 'registration_precompute_s' else 'registration', scheme, name, value)
            detail = obj['registration_details']
            for scheme, users in detail['generation_users'].items():
                if len(users) != L or [x['slot'] for x in users] != list(range(L)):
                    raise ValueError('incomplete per-user generation records')
                expected_mean = statistics.mean(x['generation_s'] for x in users)
                if not math.isclose(expected_mean, obj['registration'][scheme]['generation_mean_user_s'], rel_tol=1e-12):
                    raise ValueError('per-user generation reduction mismatch')
                for sample in users:
                    if not math.isclose(sum(sample['stages'].values()) + sample['unattributed_s'],
                                        sample['generation_s'], rel_tol=1e-12, abs_tol=1e-12):
                        raise ValueError('generation leaf accounting mismatch')
                    for metric, value in {'generation_s': sample['generation_s'],
                                          'unattributed_s': sample['unattributed_s'], **sample['stages']}.items():
                        if not math.isfinite(value) or value < 0:
                            raise ValueError('invalid per-user observation')
                        user_records.append({'L': L, 'u': u, 'round': r, 'warmup': obj['warmup'],
                            'scheme': scheme, 'slot': sample['slot'], 'metric': metric, 'seconds': value})
            for name, value in detail['preparation'].items():
                add('initialization', 'Shared', name, value)
            reference_selected = [L, u] in recipe.get('y_reference_configs', recipe['grid'] if recipe['y_reference'] else [])
            if reference_selected != ('y_reference' in detail):
                raise ValueError('checkpoint Y reference selection does not match the recipe')
            if reference_selected:
                ref = detail['y_reference']['metrics']
                for name, value in ref.items():
                    add('registration-reference', 'Individual', name, value)
                for scheme, values in [('Global', obj['registration']['Private']), ('Individual', ref)]:
                    add('y-comparison', scheme, 'Y_round_s',
                        values['Y_global_s' if scheme == 'Global' else 'Y_individual_s'])
                    add('y-comparison', scheme, 'roster_pipeline_s', values['aggregate_total_s'])
            if [L, u] in recipe['update_configs']:
                for scheme in ('R', 'F'):
                    data = obj['updates'][scheme]
                    for name, value in data['initialization'].items():
                        add('initialization', scheme, name, value)
                    if len(data['events']) != recipe['update_events']:
                        raise ValueError('wrong number of update events')
                    for name, value in data['mean_per_event'].items():
                        add('updates', scheme, name, value)
                    for name in data['events'][0]['metrics']:
                        actual = statistics.mean(e['metrics'][name] for e in data['events'])
                        if not math.isclose(actual, data['mean_per_event'][name], rel_tol=1e-12, abs_tol=1e-12):
                            raise ValueError('event reduction mismatch')
            if [L, u] == recipe['access_config']:
                for data in obj['access'].values():
                    if len(data['inner_samples']) != recipe['access_inner_repeats']:
                        raise ValueError('wrong number of access repetitions')
                    for name, value in data['mean_per_fixture'].items():
                        add('access', data['scheme'], name, value, data['K'])
                        actual = statistics.mean(e[name] for e in data['inner_samples'])
                        if not math.isclose(actual, value, rel_tol=1e-12, abs_tol=1e-12):
                            raise ValueError('access reduction mismatch')
    groups = defaultdict(list)
    indexed = {}
    for r in records:
        if not r['warmup']:
            key = (r['stage'], r['L'], r['u'], r['scheme'], r['K'], r['metric'], r['unit'])
            groups[key].append(r['value'])
            indexed[(r['stage'], r['L'], r['u'], r['scheme'], r['K'], r['metric'], r['round'])] = r['value']
    summary = []
    for key, values in sorted(groups.items()):
        if len(values) != recipe['repeats']:
            raise ValueError('incomplete independent fixture samples')
        summary.append(dict(zip(['stage', 'L', 'u', 'scheme', 'K', 'metric', 'unit'], key), **summarize(values)))
    paired = []
    for stage, control, treatment in [('registration', 'P', 'Private'), ('updates', 'R', 'F'), ('access', 'P', 'F'), ('y-comparison', 'Global', 'Individual')]:
        for row in summary:
            if row['stage'] != stage or row['scheme'] != control:
                continue
            base = (stage, row['L'], row['u'])
            keys = [(base + (treatment, row['K'], row['metric'], r), base + (control, row['K'], row['metric'], r))
                    for r in range(recipe['warmups'], recipe['warmups'] + recipe['repeats'])]
            if not all(x in indexed and y in indexed for x, y in keys):
                continue
            diff = [indexed[x] - indexed[y] for x, y in keys]
            den = statistics.mean(indexed[y] for x, y in keys)
            ratio = statistics.mean(indexed[x] for x, y in keys) / den if den > 0 else ''
            paired.append({'stage': stage, 'L': row['L'], 'u': row['u'], 'K': row['K'],
                           'control': control, 'treatment': treatment, 'metric': row['metric'], 'unit': row['unit'],
                           'ratio_of_means': ratio, **summarize(diff)})
    write_csv(out / 'timing-samples.csv', records)
    write_csv(out / 'registration-user-samples.csv', user_records)
    write_csv(out / 'registration-stages.csv', [r for r in summary if r['stage'] == 'registration'])
    write_csv(out / 'initialization-summary.csv', [r for r in summary if r['stage'] == 'initialization'])
    write_csv(out / 'y-verification-comparison.csv', [r for r in summary if r['stage'] == 'y-comparison'])
    write_csv(out / 'update-stages.csv', [r for r in summary if r['stage'] == 'updates'])
    write_csv(out / 'summary.csv', summary)
    write_csv(out / 'access-summary.csv', [r for r in summary if r['stage'] == 'access'])
    write_csv(out / 'paired-increments.csv', paired)
    material = [r for r in summary if r['unit'] == 'bytes']
    write_csv(out / 'material-sizes.csv', material)
    figdir = out / 'figures'; figdir.mkdir(exist_ok=True)
    plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 9, 'axes.spines.top': False,
                         'axes.spines.right': False, 'pdf.fonttype': 42})
    colors = {'P': '#C87941', 'Private': '#247C80', 'R': '#C87941', 'F': '#247C80'}
    def line(ax, stage, metric, schemes, axis, fixed, value):
        for scheme in schemes:
            selected = sorted([r for r in summary if r['stage'] == stage and r['metric'] == metric
                               and r['scheme'] == scheme and r[fixed] == value], key=lambda r: r[axis])
            ax.errorbar([r[axis] for r in selected], [r['mean'] for r in selected],
                        yerr=[r['ci95_half'] for r in selected], marker='o', capsize=3,
                        color=colors[scheme], label='Private registration (R/F)' if scheme == 'Private' else scheme)
        ax.set_xlabel('Roster size L' if axis == 'L' else 'Schema size u')
        ticks = sorted({r[axis] for r in summary if r['stage'] == stage and r['metric'] == metric and r[fixed] == value})
        ax.set_xticks(ticks)
        if len(ticks) == 1:
            ax.set_xlim(ticks[0] - .5, ticks[0] + .5)
        ax.set_ylabel('Time (s)'); ax.set_ylim(bottom=0); ax.grid(alpha=.2); ax.legend(fontsize=8)
    if recipe['profile'] == 'smoke' or 32 not in {r['L'] for r in summary} or 32 not in {r['u'] for r in summary}:
        fixed_u, fixed_L = recipe['grid'][0][1], recipe['grid'][0][0]
    else:
        fixed_u = fixed_L = 32
    fig, axes = plt.subplots(2, 2, figsize=(9, 6), constrained_layout=True)
    for row, metric, title in [(0, 'generation_mean_user_s', 'Mean user registration generation'),
                               (1, 'aggregate_total_s', 'KC validation and initial aggregation')]:
        line(axes[row, 0], 'registration', metric, ['P', 'Private'], 'L', 'u', fixed_u)
        line(axes[row, 1], 'registration', metric, ['P', 'Private'], 'u', 'L', fixed_L)
        axes[row, 0].set_title(f'{title}; u={fixed_u}')
        axes[row, 1].set_title(f'{title}; L={fixed_L}')
    if recipe['profile'] == 'smoke':
        fig.suptitle('SMOKE VALIDATION ONLY — not paper results')
    for ext in ('png', 'pdf'):
        fig.savefig(figdir / f'registration-cost.{ext}', dpi=180)
    plt.close(fig)
    if any(r['stage'] == 'updates' for r in summary):
        configs = recipe['update_configs']
        anchor = (32, 32) if [32, 32] in configs else configs[0]
        fixed_l, fixed_u_update = anchor
        fig, axes = plt.subplots(2, 2, figsize=(10, 6), constrained_layout=True)
        for column, axis, fixed, value in [(0, 'L', 'u', fixed_u_update), (1, 'u', 'L', fixed_l)]:
            for scheme, color in [('R', '#C87941'), ('F', '#247C80')]:
                for metric, role, style in [('revoke_prepare_s', 'Proposal', '-'), ('update_validate_s', 'KC', '--')]:
                    rows = sorted([r for r in summary if r['stage'] == 'updates' and r['scheme'] == scheme
                                   and r['metric'] == metric and r[fixed] == value], key=lambda r: r[axis])
                    axes[0, column].errorbar([r[axis] for r in rows], [r['mean'] for r in rows],
                        yerr=[r['ci95_half'] for r in rows], marker='o', linestyle=style,
                        color=color, label=scheme + ' ' + role, capsize=3)
            line(axes[1, column], 'updates', 'client_event_s', ['R', 'F'], axis, fixed, value)
            for row in range(2):
                ax = axes[row, column]
                ax.set_xlabel('Roster size L' if axis == 'L' else 'Attribute dimension u')
                ax.set_ylabel('Time per event (s)'); ax.set_ylim(bottom=0); ax.grid(alpha=.2); ax.legend(fontsize=8)
            axes[0, column].set_title('Server costs; ' + f'{fixed}={value}')
            axes[1, column].set_title('Unaffected client; ' + f'{fixed}={value}')
        if recipe['profile'] == 'smoke':
            fig.suptitle('SMOKE VALIDATION ONLY — not paper results')
        for ext in ('png', 'pdf'):
            fig.savefig(figdir / f'target-privacy-cost.{ext}', dpi=180)
        plt.close(fig)
    if recipe['y_reference']:
        fig, axes = plt.subplots(1, 2, figsize=(9, 3.5), constrained_layout=True)
        for ax, metric, title in zip(axes, ['Y_round_s', 'roster_pipeline_s'],
                                    ['Y verification only', 'Complete roster pipeline']):
            for scheme, color in [('Global', '#247C80'), ('Individual', '#C87941')]:
                rows = sorted([r for r in summary if r['stage'] == 'y-comparison'
                               and r['scheme'] == scheme and r['metric'] == metric],
                              key=lambda r: (r['u'] * r['L'] * (r['L'] - 1), r['L'], r['u']))
                ax.errorbar(range(len(rows)), [r['mean'] for r in rows],
                            yerr=[r['ci95_half'] for r in rows], marker='o', capsize=3,
                            label=scheme, color=color)
                ax.set_xticks(range(len(rows)), [f"{r['L']},{r['u']}" for r in rows])
            ax.set_xlabel('Parameter setting (L, u)'); ax.set_ylabel('Time (s)')
            ax.set_title(title); ax.set_ylim(bottom=0); ax.legend(); ax.grid(alpha=.2)
        if recipe['profile'] == 'smoke':
            fig.suptitle('SMOKE VALIDATION ONLY — not paper results')
        for ext in ('png', 'pdf'):
            fig.savefig(figdir / f'y-verification-comparison.{ext}', dpi=180)
        plt.close(fig)
    from .dynamic_report import dynamic_report
    dynamic_counts = dynamic_report(out, manifest, fixtures)
    title = '实验执行核对' if recipe['profile'] == 'formal' else '小规模验证（不可作正式实验结果）'
    lines = [f'# {title}', '', f'- [x] 每配置 {recipe["warmups"]} 个预热、{recipe["repeats"]} 个独立正式轮次；全部检查点齐全。',
             f'- [x] 源公钥验证口径：{recipe["source_validation_boundary"]}。',
             '- [x] 注册固定基预计算单列初始化成本；注册掩码在每次新注册中独立生成。',
             '- [x] 注册输入为内存对象，不含解码、网络或 ACA 审核服务。',
             '- [x] 私有注册使用紧凑证明，并且每个快照只执行一次全局 Y 校验。',
             '- [x] R/F 共用私有注册阶段，没有复制成两组独立样本。']
    for L, u in recipe['grid']:
        lines.append(f'- [x] 注册 P/Private：L={L}, u={u}。')
    for L, u in recipe['update_configs']:
        if [L, u] not in recipe['grid']:
            continue
        lines.append(f'- [x] 更新 R/F：L={L}, u={u}，每独立轮次 {recipe["update_events"]} 个合法不同单元。')
    if recipe['access_config'] and recipe['access_config'] in recipe['grid']:
        lines.append(f'- [x] 访问 P/F：配置 {recipe["access_config"]}，K={recipe["access_K"]}；先按轮次平均内部重复。')
    for L, u in recipe['history_configs']:
        lines.append(f'- [x] 离线历史 R/F：L={L}, u={u}，H={recipe["history_lengths"]}，检查点版本 {recipe["checkpoint_events"]}。')
    if recipe['y_reference']:
        lines.append(f"- [x] 已执行只读逐式 Y 参考，覆盖配置 {recipe.get('y_reference_configs', recipe['grid'])}。")
    lines += ['- [x] 所启用实验的计时外正确性自查通过。',
              '- [x] 汇总以独立轮次为样本单位；预热剔除；输出配对差值置信区间。',
              '- [x] 输出注册分项、逐用户原始记录、初始化账目及所启用实验的比较结果。', '',
              '实验配置、环境和源码指纹见 manifest.json；统计汇总由本目录检查点生成。']
    (out / 'execution-checklist.md').write_text('\n'.join(lines) + '\n')
    (out / 'validation-report.json').write_text(json.dumps({'status': 'passed', 'profile': recipe['profile'],
        'independent_repeats': recipe['repeats'], 'summary_series': len(summary), **dynamic_counts,
        'paired_increment_series': len(paired), 'formal_results': recipe['profile'] == 'formal',
        'confidence_intervals': 'two-sided Student-t 95%, independent fixtures only'}, indent=2) + '\n')
    status = json.loads((out / 'execution-status.json').read_text())
    status['status'] = 'complete'; status['report_complete'] = True
    (out / 'execution-status.json').write_text(json.dumps(status, indent=2) + '\n')
    error = out / 'last-error.json'
    if error.exists():
        error.unlink()
    print('Reports complete: ' + str(out), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('output')
    report(parser.parse_args().output)



