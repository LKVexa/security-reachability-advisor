# 0.1.2a1 — 2026-09-23

- Bind graph revision and fixed exact-boolean prerequisite declarations.
- Select deterministic shortest directed paths within explicit graph budgets.
- Replace verified-vulnerability claims with graph evidence requiring human review.
- Bind complete assessments, graphs, reports and retained state to consistency hashes.
- Add atomic capacity checks, detached exports, concurrency and 36 regressions.
- Include packaging, CI, README and Apache 2.0 LICENSE/NOTICE; certification remains open.

# Changelog — JY-S036-P001 l12-pre-merge-security-advisor

## 0.1.1-partial (2026-09-14)

Maintenance/hardening release by the JY Individual Program Audit,
Upgrade & Hardening Factory (existing-program maintenance mode).

Baseline fingerprint: build-0001 product.zip
sha256 bdbe5fc5b27681a0c2a707b8a750e1f26913a2395ceaba1deb9c5e5bff8b9a63
(14555 bytes), baseline version 0.1.0-partial, baseline tests 10/10 PASS.
All findings below were reproduced on the baseline before fixing.

### Fixed
- A026-F1 (aliasing/isolation): `advisory()` and `verify_reachability()`
  returned lists/dicts aliasing internal state. Observed: appending to a
  returned `reachable_path` mutated the stored finding and changed
  subsequent `report_digest` values. Expected: returned reports are
  isolated copies. Fix: `list()` copies of paths on every return and a
  `copy.deepcopy` of the advisory report.
- A026-F2 (error contract): malformed `flow_edges` leaked bare
  `ValueError`/`TypeError` (e.g. a 3-element edge, `None` edges), and a
  non-dict `prerequisites_met` could leak `AttributeError`. Fix: input
  validation raising the documented `AdvisorError`.
- A026-F3 (strict canonicalization): non-string alert fields were
  accepted; `float("nan")` produced a digest sealed over non-strict JSON
  (`NaN` token), and a non-serializable field leaked bare `TypeError`
  from the digest. Fix: alert fields, remediation, coverage and revision
  must be non-empty strings; `_digest` uses `allow_nan=False` and wraps
  serialization failures in `AdvisorError`.
- A026-F4 (stale verified evidence): re-verifying a VERIFIED alert
  against a graph with no path demoted it to UNVERIFIED but left stale
  `finding_digest`, `remediation`, `affected_revision`,
  `reachable_path`, `verification_coverage` on the stored alert. Fix:
  demotion strips all verified-only fields; re-verification clears a
  stale `reason`.
- A026-F5 (empty-field acceptance): `record_alert("", "", "", "")` was
  accepted; an empty source == empty sink would trivially "reach" with
  a one-node path. Fix: non-empty-string validation (shared with F3).

### Compatibility
- Public API unchanged (`SecurityAdvisor`, `record_alert`,
  `verify_reachability`, `advisory`, `AdvisorError`, `VERSION`).
- Stricter input validation: previously-accepted malformed inputs now
  raise `AdvisorError` instead of misbehaving or leaking bare built-in
  exceptions. Well-formed callers are unaffected; digests over
  well-formed inputs are unchanged.
- No baseline test asserted the old weaker behavior; all 10 baseline
  tests pass unmodified. 10 new tests added.

### Rollback
Restore build-0001 `product.zip` (sha256 above). No data formats or
persistent stores are involved; rollback is a file replacement.
