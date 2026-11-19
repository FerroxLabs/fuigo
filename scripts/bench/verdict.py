#!/usr/bin/env python3
"""Gate verdict. Usage: verdict.py <gate out dir> <out.json> <out.md>
The gate dir holds run dirs named <arm>-r<N> (arm = base|cand), each a hardbench run_suite output (results.json, summary.json).
Rules (RELEASE.md): FAIL if candidate solved tasks drop by more than 2 versus baseline. Cost per solved rising more than 10% is a
WARN only. A task is solved by an arm when every one of its attempts passed (run_suite's n*2 > reps rule with
2 repeats). Any blocked / not_run attempt makes the gate INCOMPLETE (exit 2), never a pass."""
import json, sys, glob, os, collections
from decimal import Decimal as D
gate, outj, outm = sys.argv[1:4]
MAX_DROP, MAX_COST_RISE = 2, D('0.10')
arms = collections.defaultdict(lambda: {'rows': [], 'metered': D(0), 'partial': D(0), 'unresolved': D(0), 'calls': 0, 'agent_s': 0.0, 'runs': []})
for d in sorted(glob.glob(os.path.join(gate, '*-r[0-9]*'))):
    if not os.path.isdir(d):
        continue
    arm = os.path.basename(d).rsplit('-r', 1)[0]
    try:
        rows = json.load(open(os.path.join(d, 'results.json')))
        e = json.load(open(os.path.join(d, 'summary.json')))['engines'].get('fuigo', {})
    except FileNotFoundError:
        arms[arm]['rows'].append({'task': '?', 'status': 'blocked', 'reason': 'no results in ' + d})
        continue
    a = arms[arm]
    a['rows'] += rows
    a['runs'].append(os.path.basename(d))
    a['metered'] += D(e.get('metered_cost_usd', '0')); a['partial'] += D(e.get('partial_cost_lower_usd', '0'))
    a['unresolved'] += D(e.get('unresolved_reservations_usd', '0'))
    a['calls'] += e.get('provider_calls', 0); a['agent_s'] += e.get('agent_seconds', 0.0)
out = {'arms': {}, 'rules': {'max_solved_drop': MAX_DROP, 'max_cost_per_solved_rise': str(MAX_COST_RISE)}}
for name, a in arms.items():
    per = collections.defaultdict(list)
    for r in a['rows']:
        per[r['task']].append(r['status'])
    bad = [r for r in a['rows'] if r['status'] not in ('pass', 'fail')]
    solved = sorted(t for t, s in per.items() if s and all(x == 'pass' for x in s) and len(s) >= 2)
    cost = a['metered'] + a['partial']
    out['arms'][name] = {'runs': a['runs'], 'attempts': len(a['rows']), 'passed_attempts': sum(r['status'] == 'pass' for r in a['rows']),
        'incomplete_attempts': len(bad), 'solved_tasks': len(solved), 'solved': solved, 'per_task': dict(per),
        'cost_usd': str(cost), 'unresolved_reserved_usd': str(a['unresolved']),
        'cost_per_solved_usd': str(cost / len(solved)) if solved else None, 'provider_calls': a['calls'], 'agent_seconds': round(a['agent_s'])}
b, c = out['arms'].get('base'), out['arms'].get('cand')
reasons = []
if not b or not c:
    verdict = 'INCOMPLETE'; reasons.append('missing arm')
elif b['incomplete_attempts'] or c['incomplete_attempts'] or b['attempts'] != c['attempts']:
    verdict = 'INCOMPLETE'; reasons.append('blocked/not_run attempts or unequal attempt counts')
elif any(len(s) < 2 for arm in (b, c) for s in arm['per_task'].values()):
    verdict = 'INCOMPLETE'; reasons.append('fewer than 2 repeats for some task')
else:
    verdict = 'PASS'
    if c['solved_tasks'] < b['solved_tasks'] - MAX_DROP:
        verdict = 'FAIL'; reasons.append(f"solved {c['solved_tasks']} vs base {b['solved_tasks']}: drop > {MAX_DROP}")
    if c['cost_per_solved_usd'] is None and b['cost_per_solved_usd'] is not None:
        verdict = 'FAIL'; reasons.append('candidate solved nothing')
    elif b['cost_per_solved_usd'] and c['cost_per_solved_usd']:
        rise = D(c['cost_per_solved_usd']) / D(b['cost_per_solved_usd']) - 1
        out['cost_per_solved_rise'] = str(round(rise, 4))
        if rise > MAX_COST_RISE:  # warn-only (Sean, 2026-11-17): same-binary spread measured 21%
            out.setdefault('warnings', []).append(f'WARN: cost per solved rose {rise:.1%} (> {MAX_COST_RISE:.0%}); warn-only, not a FAIL')
out['verdict'] = verdict; out['reasons'] = reasons
json.dump(out, open(outj, 'w'), indent=1)
L = [f'# Benchmark gate: {verdict}', '', *(f'- {r}' for r in reasons), *(f'- {w}' for w in out.get('warnings', [])), '',
     '| Arm | Attempts | Passed | Solved tasks | Cost USD | Cost / solved | Calls | Agent s |', '|---|---:|---:|---:|---:|---:|---:|---:|']
for n, a in out['arms'].items():
    cps = a['cost_per_solved_usd']
    L.append(f"| {n} | {a['attempts']} | {a['passed_attempts']} | {a['solved_tasks']} | {float(a['cost_usd']):.4f} | {float(cps):.4f} | {a['provider_calls']} | {a['agent_seconds']} |" if cps else f"| {n} | {a['attempts']} | {a['passed_attempts']} | {a['solved_tasks']} | {float(a['cost_usd']):.4f} | n/a | {a['provider_calls']} | {a['agent_seconds']} |")
if 'cost_per_solved_rise' in out:
    L += ['', f"Cost per solved, candidate vs base: {float(out['cost_per_solved_rise']):+.1%}"]
tasks = sorted({t for a in out['arms'].values() for t in a['per_task']})
L += ['', '| Task | ' + ' | '.join(out['arms']) + ' |', '|---|' + '---|' * len(out['arms'])]
for t in tasks:
    L.append(f'| {t} | ' + ' | '.join(''.join('P' if s == 'pass' else 'F' if s == 'fail' else '?' for s in a['per_task'].get(t, [])) for a in out['arms'].values()) + ' |')
open(outm, 'w').write('\n'.join(L) + '\n')
print(verdict)
sys.exit({'PASS': 0, 'FAIL': 1, 'INCOMPLETE': 2}[verdict])
