# Audit and hardening — 0.1.2a1

Date: 2026-09-23. Source: JY-S036-P001 / 0.1.1-partial / run-0001 / product.
Reviewed alert intake, graph traversal, evidence binding, revisions, prerequisites,
advisory semantics, state integrity and capacity. Original source remains separate.

## Repaired findings

- Truthy prerequisite values and changing/omitted names could satisfy assessments.
  Exact booleans and fixed declared or first-bound names now apply to every result.
- Equal source/sink could produce a vacuous path on an empty graph. Alert endpoints
  must differ, and traversal searches explicit directed edges.
- Path selection depended on input order and copied growing paths. Sorted/deduplicated
  edges and iterative BFS now produce a deterministic shortest path with parent links.
- Mutable revision labels and missing graph revision checks undermined evidence.
  Revision is read-only and explicit graph_revision must match on each assessment.
- Finding hashes omitted tool/rule, prerequisite values and reviewer notes.
  Complete v2 assessment/graph/report hashes and a full state seal now bind them.
- Graph reachability was called a verified vulnerability, and no verified finding
  could advise proceeding despite unassessed alerts. Results now distinguish
  GRAPH_REACHABLE/UNVERIFIED and always require review; no-alert output is NOT_ASSESSED.
- Graphs, alerts and output were unbounded. Text/edge/node/retention/report caps and
  prospective checks keep failed reassessments atomic and preserve prior evidence.
- Supported operations now serialize under an RLock and return detached outputs.
  Detected corruption blocks use; valid reassessments replace obsolete evidence.

## Verification

20 baseline tests passed. Their new-contract assertions were migrated explicitly:
graph_revision is required, GRAPH_REACHABLE replaces VERIFIED, reachable_findings
and counts.reachable replace verified names, assessment_digest replaces finding_digest,
and gate advice requires review. The source-inspection fixture now closes its file.

All 56 source and installed-wheel tests pass, with 36 new regressions covering all
64 directed three-node graphs against an independent closure calculation, a 1500-edge
chain, shortest-path tie breaking, prerequisite/revision constraints, malformed input,
atomic capacity failures, full evidence tampering, detached exports and concurrency.
CHECK_RUNS.json records current evidence; BASELINE_CHECK_RUNS.json preserves historical
evidence. CI covers Linux Python 3.10/3.12/3.14 and Windows 3.12.

No actual scanner integration, source revision verification, exploit test, throughput
benchmark, independent security audit, build-tool vulnerability scan or full original
certification was performed. There are no third-party runtime dependencies to upgrade.
The distinction from program analysis follows the scope described in the primary
[CodeQL data-flow documentation](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/):
this library only traverses supplied edges and does not construct a program model.

Version advanced from 0.1.1-partial to 0.1.2a1. Added packaging, pinned-action CI,
README, security guidance and Apache 2.0 LICENSE/NOTICE naming RUSSELL PHILIP SMITHSON.
