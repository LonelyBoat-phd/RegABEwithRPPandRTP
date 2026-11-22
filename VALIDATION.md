# Release validation

## v1.3.2

Validation used the bundled PBC source, Python 3.12 and the Python packages
listed below. The core/backend suite passed 25 tests and the experiment suite
passed 31 tests. The latter checks exact native membership dispatch, retained
source equations, matched registration admission, and the formal H=256 legal
schedule and capacity boundary.

The combined smoke recipe checks that only the selected point runs individual
Y, and that update and history stages reuse the registered fixture at shared
points. Its measurements are for pipeline validation.

```bash
python tools/build_native.py
python -m unittest discover -s tests -v
python -m unittest discover -s supplement/tests -v
python -m supplement.run --profile smoke --grid 3:4 \
  --update-grid 3:4 4:4 --y-reference-grid 2:1 \
  --history-grid 3:4 --history-lengths 1 3 --checkpoint-events 1 \
  --output results/combined-smoke-v132
```

An additional single-fixture run at `L=2, u=528` replayed H=1/8/32/128/256
from version 8 in both R and F. It verified 264 distinct legal events,
final versions, final local state and encoded response byte totals. The formal
recipe uses `L=32, u=32` for history. That formal performance grid was not run.

## v1.3.1

This release was validated as an experimental prototype. No formal-size
performance experiment was run and no timing conclusion is made from smoke data.

## Environment

- Python: 3.12.14 (main, Aug 25 2026, 14:00:49) [Clang 22.1.3 ]
- Platform: Linux-6.18.57-x86_64-with-glibc2.41
- Native PBC 0.5.14 bridge: built successfully from bundled source.
- Dependencies: cffi 2.1.1, cryptography 50.0.0, numpy 2.3.5, scipy 1.17.0, matplotlib 3.10.8

## Observed results

| Check | Result |
| --- | --- |
| Core/backend suite | 25 tests passed |
| Complete experiment suite | 29 tests passed, including 11 new second-package tests |
| Explicit update L/u scan: (3,4), (3,8), (4,4) | 9 fixture checkpoints passed, including warm-ups |
| Mid-chain replay: s=1, H=1/3, two restored inner replays | Passed within the (3,4) scan fixtures |
| Resume of complete dynamic run | All 9 checkpoints reused; reports regenerated |
| Genesis replay: s=0, H=1/4, normal update smoke | 3 fixture checkpoints passed |
| Registration global/individual Y regression: (2,1), (3,4) | 6 fixture checkpoints passed |
| Cached-source auxiliary regression: (2,1) | 3 fixture checkpoints passed |
| CSV/statistical accounting | History, paired and byte series each use n=2 independent smoke fixtures; phase sums and initialization separation checked |
| Source/archive integrity | Source manifest and embedded ZIP checksums verified during packaging |

The combined total is 54 tests. The new tests exercise parent/leaf accounting,
retained membership/signature/path checks, state equivalence with optional timing,
tamper rejection without installation, exact encoded byte totals, matched R/F
history schedules, restored replay repetitions, nonzero checkpoints, partitioned
replay, missing parents, invalid capacities, explicit stage grids and rejection
of incomplete history/control records.

Smoke has one discarded warm-up and two measured independent fixtures per point.
Inner replay repetitions and H events are not independent confidence-interval
samples. The scan produced 40 history summary series, 16 paired history series
and 204 byte-component series, each with n=2; these counts validate reporting,
not empirical performance claims. Histories use only legal distinct committed
events and an unaffected observer. Byte components match the existing encoders,
with framing and repeated authenticated objects included.

No service expansion, full decoder, network acquisition, memory/density study or
new algorithmic optimization was added. Access performance remains opt-in;
existing access correctness probes run outside reported timers. Private masks,
keys and checkpoints are not exported. Build products, environments and results
are excluded from the source ZIP.

## Reproduce

Install prerequisites using README.md, then:

```bash
python3 tools/build_native.py
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s supplement/tests -v
python3 -m supplement.run --profile smoke --grid 3:4 --update-grid 3:4 3:8 4:4 --history-grid 3:4 --history-lengths 1 3 --checkpoint-events 1 --history-replays 2 --output results/dynamic-validation
python3 -m supplement.run --profile smoke --grid 3:4 --update-grid 3:4 3:8 4:4 --history-grid 3:4 --history-lengths 1 3 --checkpoint-events 1 --history-replays 2 --output results/dynamic-validation
python3 -m supplement.run --profile smoke --grid 3:4 --history-lengths 1 4 --update-events 2 --output results/genesis-validation
python3 -m supplement.run --profile smoke --registration-only --y-reference --grid 2:1 3:4 --output results/registration-validation
python3 -m supplement.run --profile smoke --registration-only --source-validation cached --grid 2:1 --output results/cached-validation
python3 tools/check_integrity.py
```

The source/schema differs from v1.3.0; use new result directories. CI includes
these test families and the small explicit update/history scan with resume.
