# Security Reachability Advisor

**0.1.2a1 — experimental partial candidate, JY-S036-P001 / L12**

Record security alerts and assess source-to-sink reachability on a caller-supplied
directed graph. The result is review evidence, not a verified vulnerability,
source-code analysis or permission to merge. No network, file or code execution
is performed. Python 3.10+; no third-party runtime dependencies.

## Use

~~~sh
python -m pip install .
python -m unittest discover -s tests -t .
~~~

~~~python
from l12.core import SecurityAdvisor

advisor = SecurityAdvisor("revision-123")
alert = advisor.record_alert("scanner", "untrusted-query", "request", "query",
                             required_prerequisites=["input_untrusted"])
result = advisor.verify_reachability(
    alert["alert_id"], [("request", "handler"), ("handler", "query")],
    {"input_untrusted": True}, remediation="Use bound query parameters",
    coverage="Reviewer must execute the injection regression test",
    graph_revision="revision-123")
assert result["status"] == "GRAPH_REACHABLE"
assert result["vulnerability_verified"] is False
assert advisor.verify()["verdict"] == "PASS"
report = advisor.advisory()
~~~

## Evidence and decisions

The advisor revision is read-only. Every assessment must explicitly declare the
same graph_revision. This compares caller labels; it does not inspect Git or
prove that a graph corresponds to source code at that revision.

Source and sink must be distinct exact node IDs. Edges are directed, sorted and
deduplicated. An iterative breadth-first search chooses a shortest path with
lexicographic neighbor tie breaking. Cycles terminate. An absent path says only
that the supplied graph does not connect the endpoints.

prerequisites_met must be a dictionary of exact booleans. Required prerequisite
names can be declared on record_alert. If omitted, names bind on the first
successful valid assessment. Subsequent assessments must use exactly those names;
create a new alert to change the declaration. An explicit empty list is allowed.
Neither an empty declaration nor all-true values prove completeness or truth.

A path with every declared prerequisite true yields GRAPH_REACHABLE and requires
nonblank remediation and coverage notes. Other valid assessments are UNVERIFIED.
The output explicitly sets prerequisite_claims_verified,
prerequisites_exhaustive_verified, coverage_executed and vulnerability_verified
to false. Remediation and coverage are caller prose; tests are not executed.

advisory() returns schema l12/advisory/v2 with reachable_findings,
unverified_alerts and counts. Any recorded alert yields ADVISE_REVIEW; an empty
advisor yields NOT_ASSESSED. It never advises proceeding or performs a merge/block
action. Human review must establish actual source flow, sanitizers, edge-specific
conditions, runtime behavior, prerequisite completeness and exploitability.

## State, limits and integrity

Invalid or over-budget reassessments leave the prior successful assessment intact.
A valid reassessment replaces its prior graph and evidence, including demotion
to UNVERIFIED; historical assessments are not retained. assessment(alert_id)
exports a detached current graph/assessment pair. All returned reports and
assessments are detached. An RLock serializes supported state operations.

Text is exact, case-sensitive, valid Unicode without C0/DEL controls. Nonblank
values may contain leading/trailing spaces, which remain significant. Byte limits:
256 for revision/tool/rule, 128 for node/prerequisite IDs, 4096 for each remediation
or coverage note. There are at most 64 unique prerequisite names per alert.

Capacities: 250 alerts, 10000 input edge pairs, 5000 distinct graph nodes, 1 MiB
canonical sorted edge bytes, 8 MiB retained graph objects and 4 MiB prospective
advisory bytes. Replacements reclaim the prior graph's accounted bytes. Duplicate
edges count toward the input edge cap. Canonical JSON uses sorted keys, compact
separators and ASCII escapes; Unicode escaping counts toward byte capacities.

Assessment schema l12/assessment/v2 binds all fields, including notes,
prerequisites, tool/rule, revision, path and graph digest. Graph schema
l12/flow-graph/v2 binds revision and complete edges. The report digest covers its
complete output; the state digest also covers retained alerts, graphs, assessments,
ID counter and byte counter. verify() reports integrity PASS/FAIL. Detected private
state corruption blocks record, assess, advisory and assessment export calls with
IntegrityError, a subclass of AdvisorError.

These are unsigned consistency hashes, not authentication or an externally
anchored audit trail. A process owner can rewrite data and hashes. Limits bound
normal accepted workloads, not OS memory/time. Full retained-state hashing and
report copying cost grows with data. There is no persistence, authorization,
source scanner, CVE lookup, exploit validation or hostile-process isolation.

## Verification and migration

56 tests: 20 inherited tests updated for the new evidence contract plus 36 new
regressions. They cover all 64 directed three-node graphs, long chains, stable
shortest paths, strict prerequisites, revision binding, atomic budget failures,
complete metadata tampering, detached views and concurrent alert IDs.
Source and installed-wheel results: [CHECK_RUNS](docs/CHECK_RUNS.json).
CI covers Linux Python 3.10/3.12/3.14 and Windows 3.12. See [AUDIT](docs/AUDIT.md).

0.1.1-partial -> 0.1.2a1 intentionally changes the contract: provide graph_revision,
replace VERIFIED with GRAPH_REACHABLE, verified_vulnerabilities with
reachable_findings, counts.verified with counts.reachable and finding_digest with
assessment_digest. Gate output is now ADVISE_REVIEW or NOT_ASSESSED. Regenerate
v2 evidence; old digests are not interchangeable. Existing source==sink alerts
must be modeled with distinct endpoint IDs. Broader certification remains open.

## License

Copyright 2026 **RUSSELL PHILIP SMITHSON**.
[Apache License 2.0](LICENSE), with [NOTICE](NOTICE).
No third-party source is vendored; see [THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES.md).
