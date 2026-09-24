# Security boundaries

This local library checks a supplied directed graph and unverified prerequisite
claims. It neither analyzes program source nor confirms a vulnerability. Revision
labels are caller declarations. An absent path does not prove safety, and a
reachable path does not prove exploitability. All alerts require human review.

Caller notes are not executed coverage or validated remediation. Sanitizers,
edge conditions, runtime semantics and complete prerequisites must be assessed
outside this library. No automated merge, block or network behavior is present.

Unsigned hashes detect consistency changes, not a process owner rewriting state
and hashes. The object has no authorization or durable audit history. Current
assessments replace prior ones; preserve exports externally when history matters.
Graph labels and notes can contain sensitive source details; the caller controls
access, retention and transmission. Input bounds are normal-workload controls,
not a sandbox or OS resource quota. No independent audit, build-tool vulnerability
scan or full original certification is claimed.
