#!/usr/bin/env python3
"""Copy a hardbench harness dir and point its 'anthropic' profile at the Flux Anthropic-compatible endpoint.

Usage: mk-gate-harness.py <hardbench harness dir> <dest dir>
Only profiles.py changes: the origin (env GATE_ORIGIN, default https://api.fluxrouter.ai/anthropic, so the gateway's
/anthropic/v1/messages -> <origin>/v1/messages) and the provider-key prefix check (a Flux key is not sk-ant-).
Model, rates, effort and every other control stay as frozen for the 2026-10-13 benchmark.
"""
import os, shutil, sys
src, dest = sys.argv[1], sys.argv[2]
shutil.copytree(src, dest)
p = os.path.join(dest, 'profiles.py')
t = open(p).read()
old = "'origin': 'https://api.anthropic.com'"
assert t.count(old) == 1, 'anthropic origin not found exactly once'
t = t.replace(old, "'origin': %r" % os.environ.get('GATE_ORIGIN', 'https://api.fluxrouter.ai/anthropic'))
sig = 'def validate_key_provider(profile, key):\n'
assert t.count(sig) == 1
t = t.replace(sig, sig + '    return  # gate overlay: the Flux key has no provider prefix; origin is fixed above\n', 1)
open(p, 'w').write(t)
