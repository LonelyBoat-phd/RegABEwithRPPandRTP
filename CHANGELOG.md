# Release notes

## Unreleased - packaging and single-protocol normalization

- Flattened the artifact to one repository root: the implementation, its release
  documents and the operator `runbook/` now live side by side instead of in a
  nested snapshot directory.
- Normalized every timing entry point to one protocol: 10 discarded warm-up
  fixtures and 50 independent measured fixtures per point. Runbook scripts no
  longer carry ad-hoc 0/2, 1/6, 2/10 or 0/3 overrides, and `bench.py` now defaults
  to the same 10/50.
- Rewrote `runbook/`: nine campaign scripts became five numbered entry points plus
  `progress.sh` and `probe_run.sh`; absolute operator paths, the Windows/WSL
  launcher wrappers and the dated pacing plans were removed. Scripts now resolve
  the repository root themselves, log to `results/_logs/`, and honour
  `REGABE_PY`/`REGABE_LOGDIR`.
- Added `README.zh-CN.md`, `.gitattributes` (LF everywhere except the vendored
  archive) and `logs/` to `.gitignore`.
- Removed the internal `LOCAL-CHANGES.patch` diff, the stale v1.3.1 runbook
  README, and the UTF-8 BOM / CRLF editor residue.
- `tools/check_integrity.py` now excludes `runbook/` and `logs/` so operator
  tooling and run output cannot make the source manifest stale.
- No cryptographic construction, timing boundary or result schema changed.

## 1.3.2 - fixture reuse, exact native membership, and H=256

- Limit individual Y to selected points in a combined recipe and run generic
  P/R/F access probes in the test suite. Existing per-workload checks remain.
- Use the native exact membership batch for source keys and complete Full update
  vectors. Pairing equations and all authenticated inputs remain covered.
- Encode only response objects for history byte accounting. Add H=256 to the
  formal recipe and cross-check legal event capacity and replay.

## 1.3.1 - update and committed-history work package

- Added optional RA/KC/client lexical phase timers, parent residual accounting and
  matching public-target timing. Existing security checks remain in place.
- Added explicit update/history grids, legal event budgets and checkpoint/replay
  options. Explicit stage points are unioned into the fixture grid.
- Added offline replay from a retained checkpoint, matched R/F schedules, online
  reference checks, restored inner repeats and fixture-level statistics.
- Added exact encoded registration, publication, response and history byte ledgers,
  including all framing and repeated Heads/signatures; no decoder is introduced.
- Moved authority initialization out of per-event means into an initialization
  record. Extended CSV outputs, L/u and H plots, CI/resume coverage and docs.
- Density/memory experiments, service expansion and new optimizations remain out
  of scope. v1.3.0 result directories cannot resume under the changed source/schema.


## 1.3.0 - registration measurement work package

- Moved fresh per-registration masks out of SourceSecret/SourceKeyGen into RegGen.
  SourceSecret now has only slot/zeta; the old source_keygen(..., xi=...) argument
  is removed. Static-reference keygen was adjusted accordingly.
- Included complete source validation in the default timed roster pipeline;
  retained cached validation as an explicitly charged auxiliary mode.
- Separated shared public registration fixed-base setup from user generation.
- Added individual-call generation stages and global-Y weights/MSM/pairing timing.
- Added an opt-in same-record deterministic Y reference with matching input checks,
  alternating order, no redundant per-equation membership tests, and no runtime
  installation or main-verification fallback.
- Added first-work-package CLI controls, raw records and summary outputs; access
  performance is opt-in. Existing cryptographic wire format is unchanged, but
  experiment schemas/timing boundaries changed: use new output directories.
- Added boundary and regression tests. Service-level ACA/registry/authorization
  expansion, decoding, update decomposition and offline history remain out of scope.


## 1.2.1 - source artifact cleanup

- Consolidated installation, evaluation, and scope documentation into README.md.
- Removed duplicate documentation, historical tuning outputs, old-version comparison tools, and the obsolete long-history benchmark entrypoint.
- Distributed source instead of a machine-specific native binary and build paths.
- Unified the default experiment script with the manuscript P/R/F evaluation.
- Added source integrity checking, source-build CI, and generated-file exclusions.
- Preserved the cryptographic implementation, fixed parameters, optimization configuration, and evaluation sample settings from the supplied 1.2 archive.
- Kept provenance and third-party notices; no new project license was assigned.
