# RegABE reference implementation — v1.3.2

Research prototype for **Registered Attribute-Based Encryption with Private
Registration and Versioned Attribute Revocation**. Version 1.3.2 keeps the
registration-analysis work package and adds update decomposition, explicit L/u
scans, offline committed-history replay and exact encoded byte-component
accounting. It is not a full service implementation of every manuscript
interface. Release history is in `CHANGELOG.md`; observed validation results are
in `VALIDATION.md`; the scripts that produced the reported data are in `runbook/`.

## Measurement protocol (unified)

Every reported timing point uses **one** protocol. There is no second convention
anywhere in this repository: not in the profile defaults, not in the CLI
examples, not in `runbook/`, not in `bench.py`.

| Item | Value | Role |
| --- | --- | --- |
| `--warmups` | **10** | discarded fixtures per point; never enters statistics |
| `--repeats` | **50** | independent measured fixtures per point (n=50) |
| fixtures per point | **60** | 10 + 50 |
| `--profile smoke` | 1 + 2 | pipeline/resume validation only; no performance claim |
| inner repeats | `access_inner_repeats=5`, `history_replays=1` | averaged inside one fixture, not independent samples |

The numbers are the profile defaults in `supplement/run.py::make_recipe`, are
asserted by `supplement/tests/test_supplement.py::test_formal_sample_counts`, and
are written into `manifest.json`, where resume re-checks them. Every script in
`runbook/` passes `--warmups 10 --repeats 50` explicitly so the recipe is visible
in the shell history as well as in the manifest.

Confidence intervals are two-sided 95% Student-t intervals over the 50 independent
fixtures. Inner access repetitions and history replay repetitions are averaged
within their fixture and are **not** treated as independent observations.

## Repository layout

| Path | Content |
| --- | --- |
| `regabe/` | cryptographic core: primitives, registration, revocation, history, metrics |
| `supplement/` | experiment layer: recipe/manifest, protocol drivers, reports, CSV/plots, tests |
| `native/type1.c` | PBC Type-1 bridge (compiled at build time, never shipped) |
| `vendor/` | unmodified PBC 0.5.14 source archive and its license |
| `params/` | fixed Type A parameters |
| `tests/`, `supplement/tests/` | backend/protocol suite and experiment suite |
| `tools/` | native build, source-integrity check, parameter generation |
| `runbook/` | the operator scripts that produced the reported data (see `runbook/README.md`) |
| `example.py`, `bench.py` | minimal protocol example; legacy external static-reference bench |

## Runbook

`runbook/README.md` documents the exact execution order, the fixtures per step,
the runtime budget, the resume rules and the result-file mapping. The entry
points are `runbook/01_run_formal_main.sh` … `runbook/05_run_memory.sh`, with
`runbook/progress.sh` as a read-only progress panel. `runbook/` is deliberately
outside `SHA256SUMS`: it is tooling meant to be adapted, not release source.

## Installation

Linux/WSL2, Python 3.12+, a C compiler and GMP development headers are required.
The release includes the PBC 0.5.14 source archive and fixed Type A parameters.

```bash
bash setup.sh
.venv/bin/python example.py
```

`setup.sh` verifies source integrity, creates a virtual environment, installs core
requirements, builds the native bridge, and runs both test suites. For a manual
installation in an existing environment:

```bash
python3 -m pip install -r supplement/requirements.txt
python3 tools/build_native.py
```

`requirements-validation.lock` retains the supplied validated dependency recipe;
`VALIDATION.md` records the environment actually used for this release. Generated
libraries are not shipped. No wheel/PyPI distribution is supplied.

## What changed in 1.3.2

- Source-key validation and KC's Full update-vector validation use the existing
  native batch interface. Every point still receives an exact curve and subgroup
  check. Source-key pairing equations are still checked individually.
- A single fixture at each point serves all requested stages. Use
  `--y-reference-grid` to time individual Y only at selected points, including
  points shared with update/history scans. Generic P/R/F access checks run in
  the test suite. The driver retains the checks specific to each enabled stage.
- History byte accounting encodes only the client response when it needs only
  response bytes. The formal example includes H=256 and checks legal capacity
  before starting. For the release details, see `RELEASE_v1.3.2_ZH.md`.

## What changed in 1.3.1

- Added optional disjoint RA, KC and client leaf timers without removing existing
  signature, membership, Merkle-path or progression checks. Proposal material
  extraction/path preparation is separately named; proposal totals are not
  mislabeled as pure RA arithmetic. Residuals reconcile leaves with parent totals.
- Added `--update-grid` for explicit L/u update scans and `--update-events` for the
  number of legal distinct events. Explicit stage grids are unioned into the
  fixture grid so requested stage points are not silently skipped.
- Added opt-in offline history replay from genesis or a nonzero committed version.
  Every inner replay restores the same checkpoint before timing, authenticates
  all H committed events, and is checked against an online reference outside the
  timer. R/F use matched legal schedules and an unaffected observer.
- Added exact registration/publication/client-response byte components, including
  framing, repeated Heads/signatures, corrections and both Merkle paths.
- Added fixture-level history statistics, paired increments and raw inner records;
  history generation, local material preparation, checkpoint restoration and byte
  accounting remain separate from replay processing time.
- Kept the public-target/Full algebra and wire formats; no decoding, network or
  service expansion was introduced. Density, memory and new optimizations remain
  future work. See `RELEASE_v1.3.1_ZH.md` for the Chinese release guide.

## Retained registration work from 1.3.0

- `SourceSecret` contains only slot and source scalar. RegGen samples fresh
  registration masks and an opening on every new invocation, retaining them in
  `RegistrationWitness`. Exact retransmission reuses the retained record.
- Complete source-key validation is included in the measured P and Private roster
  pipelines by default. Cached receipts are an explicitly auxiliary mode; their
  full preparation cost is recorded separately.
- Shared public registration fixed-base tables are built once per fixture and
  charged to `registration_precompute_s`, outside per-user generation and roster
  validation. Table lookup/binding checks remain inside subsequent calls.
- Generation records individual user calls and nonoverlapping leaf phases:
  randomness, commitment, X, Y, splits, local certificate signing, proof first
  messages, challenge and responses. Global Y records weights, MSM and pairing.
- Optional deterministic individual-Y evaluation uses the same records and
  validation rules. It repeats no per-equation membership checks after the common
  validation phase. It is read-only and never installs state or replaces a failed
  global admission. Exactly one global round remains the main admission.
- Access timing is excluded by default. Existing P/R/F update and access code is
  retained; update decomposition and offline history drivers are added in 1.3.1.

## Configurations

| Label | Registration | Revocation target |
| --- | --- | --- |
| P | Certified, public | Public |
| R | Certified, private | Public |
| F | Same private registration as R | Hidden |
| Private | Shared R/F registration measurement | Not applicable |

P and Private share parameters, profiles and source keys in each fixture. R and F
share the accepted private registration. Public-target updates already compute the
changed helper block and its authentication state; they are not zero-cost updates.

## Second-work-package examples

```bash
# Small L/u scan plus mid-chain offline replay; pipeline validation only.
bash run_experiments.sh --profile smoke --grid 3:4 \
  --update-grid 3:4 3:8 4:4 --history-grid 3:4 \
  --history-lengths 1 3 --checkpoint-events 1 --history-replays 2 \
  --output results/second-batch-smoke-v131

# Combined formal recipe. Each point gets one registration fixture per round.
bash run_experiments.sh --profile formal --warmups 10 --repeats 50 \
  --update-grid 16:32 32:32 64:32 32:64 32:128 \
  --y-reference-grid 4:8 8:8 \
  --history-grid 32:32 --history-lengths 1 8 32 128 256 \
  --checkpoint-events 8 --output results/formal-v132
```

History is opt-in via `--history-lengths`. Without `--history-grid` it uses the
selected update points, or the supplied fixture points if none are selected.
`--registration-only` rejects conflicting update/history requests. Explicit
`--update-grid` and `--history-grid` points are added to the fixture grid, so every
one receives a fresh matching registration. Default update points are limited to
those present in the chosen fixture grid. No Cartesian product is generated.

The workload reserves user 0 (all qualifications) as an unaffected observer;
other users have exactly floor(u/2) available attributes. A history consumes
`checkpoint-events + max(history-lengths)` distinct active user-attribute pairs,
which must not exceed (L-1)*floor(u/2). Update trials have a separate runtime and
schedule; their event budget is checked separately. Invalid capacities are
rejected before fixture generation, never silently clipped or padded with retries.

## Run experiments

Both shell entrypoints use `supplement.run`. They check release integrity, install
missing experiment dependencies, build the bridge if necessary, and run the
supplement tests. `REGABE_PYTHON` selects an existing Python interpreter.

```bash
# Small pipeline validation only; not manuscript performance results.
bash run_experiments.sh --profile smoke --output results/smoke-v130

# First work package only: same-record global/individual Y comparison.
bash run_experiments.sh --profile smoke --registration-only --y-reference \
  --grid 2:1 3:4 --output results/registration-smoke-v130

# Main formal registration workload, complete source validation included.
bash run_experiments.sh --profile formal --registration-only \
  --output results/registration-formal-v130

# Small explicit points for a deterministic reference (quadratic pairing work).
bash run_experiments.sh --profile formal --registration-only --y-reference \
  --grid 4:8 8:8 --output results/y-reference-formal-v130

# Auxiliary cached-source mode; do not mix its results with the main mode.
bash run_experiments.sh --profile smoke --registration-only \
  --source-validation cached --output results/cached-source-v130
```

The individual reference performs u*L*(L-1) equation checks and can be expensive.
`--y-reference-grid` limits this reference to the specified points and adds any
missing points to the fixture grid. The existing `--y-reference` flag enables it
at every point in the effective grid. Use a new output directory for v1.3.2.
`--grid` selects initial fixture points; explicit update/history grids add their points, without a Cartesian product. `--registration-only`
disables update timing. `--include-access` explicitly enables the legacy access
measurements; `--skip-access` remains a compatible no-op. Update and measured
access workloads retain their own correctness checks outside measurement timers.

The reported formal registration grid is (8,32), (16,32), (32,32), (64,32),
(32,16), (32,64), (32,128); `--grid` selects the points and the profile default
subset is (16,32), (32,32), (64,32), (32,64), (32,128). Under the unified protocol
each point has 10 discarded warm-up fixtures and 50 measured independent
fixtures, so the reported grid is 7 × 60 = 420 fixtures. Smoke uses one warm-up
and two measured fixtures and is never reported as a performance result. No
formal result files are shipped with this source release.

## Measurement contract

Measured inputs are pre-existing **in-memory objects**. No object-level decoder,
transport or from-wire-input-to-installation timing is implemented or claimed.
Canonical record lengths are counted separately before roster verification;
both Y variants therefore start with equally populated element encoding caches.

Generation includes local record construction, fresh masks/proof randomness and
certificate signing. It does **not** include an ACA evidence/opening review service
or source-key generation/verification. The full roster pipeline includes owned
snapshot pinning, complete source validation, certificate/proof validation,
membership tests, one global Y round, aggregation and the existing authentication
structures. The optional individual reference executes that same pipeline on the
same records, replacing only the Y equation evaluation; execution order alternates
across fixtures. Its candidate is checked against the main candidate but discarded.

There is no cold-user latency claim: registration tables are shared public
precomputation built once per context. Their initialization time is reported
separately; `generation_mean_user_s` is the mean of individually timed user calls.
`generation_total_s` additionally includes driver dispatch/collection, whose time
is separately recorded. `gen_*_s` fixture aggregates use a **roster** unit.

Total timers and leaf timers overlap by design and must never be summed together.
The parent roster phases are snapshot, record verification, Y membership, Y round,
products and authenticated-state construction. Source/certificate/proof phases
are children of record verification; weights/MSM/pairing are children of the Y
round. Residual fields preserve uninstrumented work and timer overhead.

The optional cached-source mode still performs full validation during preparation,
records `source_validation_prepare_s`, and validates bound local receipts inside
the measured pipeline. Its narrower pipeline time is not the full-source result.
No required checks are skipped in either mode.

Update timers and byte counts retain their previous boundaries. `fetch_local_s`
means local material preparation/extraction, **not** network acquisition. Authority
initialization, commit installation, material acquisition and network delivery
are outside the reported update algorithm timers (some are recorded separately).

## Update and offline-history timing details

`revoke_prepare_s` includes `proposal_material_s` (and, for Full,
`proposal_path_s`) plus RA stages: checks, PRF/FieldMap, precompute lookup,
correction group operations, successor arithmetic, helper-tree construction,
delta authentication, pending snapshot/copy and Head authentication. Some stages
exist only in Full. The public deterministic control derives its corrections
from trusted parameters instead of receiving and validating an external vector.

`update_validate_s` covers KC snapshot, RA signature, metadata/counters, Full
vector membership and authentication, successor arithmetic/helper tree,
attribute-state update, descriptor/Head checks and output signing/staging.
`client_event_s` covers input, authentication, bindings, Full correction membership
and paths, progression, Full PRF/self-test and local state changes. Existing
length-u container copying is retained and timed; no asymptotic optimization is
assumed. RA initialization is now stored under `updates[scheme].initialization`,
not a per-event average. `fetch_local_s` and `commit_install_s` remain separate.

Offline history reports `catchup_processing_s`: only the loop of normal client
processing over H prebuilt memory objects, including checks and state updates.
Checkpoint creation/restoration, history construction, local sync material
extraction, online-reference processing and encoding/accounting are excluded and
recorded under `preparation`. These preparation totals cover the committed prefix
plus the maximum requested H (restores cover all requested repetitions). They
are not a download-time or per-H acquisition measurement. Every repetition starts
from the same private checkpoint; partial/prefix replays are not reused as timed
starting points. Empty, duplicate, excessive or invalid history recipes fail.
Only successful committed events enter H; no aborted proposal, cached retry or
idempotence probe is counted. Expected online state is retained only in memory;
private masks, keys and checkpoints are never written to result files.

Byte components come from the existing real encoders, not object heap sizes or
asymptotic formulas. `total_bytes` equals the sum of the disjoint components.
Named source/certificate/event/path representations include their internal
framing; the remaining `framing_bytes` accounts for other wrappers. Publications
count both proposal and receipt, including two Head encodings and their actual
signature occurrences. Client responses count both paths separately without
hypothetical multiproof deduplication. These are protocol object bytes, excluding
transport headers. Benchmark schedule labels in raw files are workload truth,
not a claim that a Full public update reveals the target.

## Outputs and statistics

- `manifest.json`: source/environment/parameter identities and measurement policy.
- `rounds/*.json`: fixture records, per-user stage records, preparation and optional
  Y-reference metadata. Cryptographic witnesses, masks and weights are not saved.
- `timing-samples.csv`, `summary.csv`, `paired-increments.csv`: fixture observations,
  confidence intervals and matched increments.
- `registration-user-samples.csv`: raw individual calls; users in one fixture are
  not treated as independent confidence-interval samples.
- `registration-stages.csv`, `initialization-summary.csv`: phase and initialization
  tables. Empty optional outputs are omitted.
- `y-verification-comparison.csv` and optional plots: local Y and complete-pipeline
  comparisons, separately identified from main admission.
- `update-event-samples.csv`, `update-stages.csv`: per-event raw times and
  fixture-level update phase summaries.
- `byte-components.csv`, `byte-components-summary.csv`: raw and fixture-level
  registration-roster, per-event publication/response and cumulative history bytes.
- `history-samples.csv`, `history-inner-samples.csv`, `history-summary.csv`,
  `history-paired-increments.csv`: independent-fixture history statistics.
- `history-initialization-samples.csv`, `history-preparation-samples.csv`: costs
  excluded from replay timers, explicitly kept out of per-event processing.
- `material-sizes.csv`, `figures/`, execution and validation reports.

Statistics use independent fixture means and two-sided 95% Student-t intervals;
matched differences use the same fixture. Ratios are ratios of means, without a
ratio confidence interval. Generation stages are roster totals unless marked
`mean_user`; global/individual comparison is within each fixture. Workload seeds
do not seed cryptographic randomness. History repeats are averaged inside each fixture; H prefixes remain correlated.
Byte observations from multiple update events are averaged inside each fixture
before computing intervals. Object sharing and precomputation policy are fixed
in the recipe.

Resume requires matching source, parameters, environment and recipe. Use a new
output directory after changes. To regenerate reports:

```bash
.venv/bin/python -m supplement.report results/registration-smoke-v130
```

## Tests and source integrity

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m unittest discover -s supplement/tests -v
python3 tools/check_integrity.py
```

New regression tests check fresh registration masks, in-timer complete source
validation, explicit cached preparation, precompute boundaries, timer accounting,
matching Y checks, and no fallback from failed global verification. Existing
protocol/backend tests are retained. See `VALIDATION.md` for observed results.

After intentional source edits, refresh `SHA256SUMS` using
`python3 tools/check_integrity.py --write`. It checks release consistency, not
publisher authenticity. `bench.py` remains the legacy external static-reference
utility with its own untimed-source-validation contract; it is not the v1.3 main
registration experiment. `regabe.experiment.build(exclude_isvalid=True)` also
retains its explicitly narrower legacy mode.

## Deliberate scope limits

ACA review, original enrollment binding services, complete registry-to-Base
binding, complete role/encoding alignment, protected authorization workflow,
durable atomic commits, persistent nonce journals and crash recovery are not
added in this work package. Existing signing, authentication paths, group checks
and version checks remain in the measured algorithms. Drivers construct legal
normal histories; this is not a deployed authorization service. The current
object/identity bindings are not a claim of complete manuscript service fidelity.

The prototype is serial and uses variable-time arithmetic. It preserves the fixed
roster/schema model. Retained matching historical materials can access earlier
versions. Tests and timings do not establish RPP/RTP security or production safety.

## Provenance and licensing

Project-specific code was generated using AI tools; see `NOTICE`. No project-wide
open-source license is assigned: this repository ships **no `LICENSE` file**, so
default copyright applies and nobody may redistribute it until the rights holder
chooses one. `vendor/PBC-COPYING` and the dependency licenses are unaffected.
Cite a fixed release or commit with the manuscript.
