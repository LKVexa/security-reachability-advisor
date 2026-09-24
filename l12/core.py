"""Bounded graph reachability evidence for human security review, not a scanner."""
from __future__ import annotations

from collections import deque
import copy
import hashlib
import json
import threading

VERSION = "0.1.2a1"
MAX_ALERTS = 250
MAX_EDGES = 10000
MAX_NODES = 5000
MAX_GRAPH_BYTES = 1048576
MAX_TOTAL_GRAPH_BYTES = 8388608
MAX_REPORT_BYTES = 4194304


class AdvisorError(Exception):
    pass


class IntegrityError(AdvisorError):
    pass


def _canonical(obj):
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode()
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise AdvisorError("invalid canonical data") from exc


def _digest(obj):
    return "sha256:" + hashlib.sha256(_canonical(obj)).hexdigest()


def _require_str(name, value, maximum=256):
    if type(value) is not str or not value.strip() or len(value) > maximum:
        raise AdvisorError(name + " must be bounded nonblank text")
    try:
        if len(value.encode()) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise AdvisorError(name + " exceeds text bounds or contains controls")
    except UnicodeError as exc:
        raise AdvisorError(name + " contains invalid Unicode") from exc
    return value


def _prerequisites(value):
    if type(value) is not dict or len(value) > 64:
        raise AdvisorError("prerequisites_met must be a dictionary of at most 64 exact booleans")
    clean = {}
    for key, met in value.items():
        _require_str("prerequisite", key, 128)
        if type(met) is not bool:
            raise AdvisorError("prerequisite values must be exact booleans")
        clean[key] = met
    return {k: clean[k] for k in sorted(clean)}


class SecurityAdvisor:
    def __init__(self, revision):
        self._revision = _require_str("revision", revision)
        self._alerts = {}
        self._assessments = {}
        self._graphs = {}
        self._graph_bytes = 0
        self._n = 0
        self._lock = threading.RLock()
        self._seal = self._state_hash()

    @property
    def revision(self):
        return self._revision

    def _state_hash(self):
        return _digest({"revision": self._revision, "alerts": self._alerts,
                        "assessments": self._assessments, "graphs": self._graphs,
                        "graph_bytes": self._graph_bytes, "next_id": self._n})

    def _problems(self):
        problems = []
        try:
            for aid, assessment in self._assessments.items():
                if (assessment["assessment_digest"] != _digest({
                        k: v for k, v in assessment.items() if k != "assessment_digest"})
                        or assessment["graph_digest"] != _digest(self._graphs[aid])):
                    problems.append(aid)
            if self._state_hash() != self._seal:
                problems.append("state")
        except (AdvisorError, KeyError, TypeError, AttributeError):
            problems.append("state")
        return problems

    def _require_integrity(self):
        if self._problems():
            raise IntegrityError("advisor state integrity failed")

    def record_alert(self, tool, rule, source, sink, required_prerequisites=None):
        fields = {"tool": _require_str("tool", tool), "rule": _require_str("rule", rule),
                  "source": _require_str("source", source, 128),
                  "sink": _require_str("sink", sink, 128)}
        if source == sink:
            raise AdvisorError("source and sink must use distinct graph node IDs")
        required = None
        if required_prerequisites is not None:
            if type(required_prerequisites) is not list or len(required_prerequisites) > 64:
                raise AdvisorError("required_prerequisites must be a list of at most 64 names")
            required = [_require_str("prerequisite", p, 128) for p in required_prerequisites]
            if len(set(required)) != len(required):
                raise AdvisorError("prerequisite names must be unique")
            required.sort()
        with self._lock:
            self._require_integrity()
            if len(self._alerts) >= MAX_ALERTS:
                raise AdvisorError("alert capacity exceeded")
            aid = f"alert-{self._n + 1:04d}"
            alert = {"alert_id": aid, **fields, "status": "UNVERIFIED",
                     "affected_revision": self._revision,
                     "required_prerequisites": required,
                     "reason": "no graph assessment supplied"}
            prospective = dict(self._alerts, **{aid: alert})
            self._report_budget(prospective, self._assessments)
            self._alerts[aid] = alert
            self._n += 1
            self._seal = self._state_hash()
            return {"alert_id": aid, "status": "UNVERIFIED"}

    @staticmethod
    def _validated_edges(flow_edges):
        if type(flow_edges) is not list or len(flow_edges) > MAX_EDGES:
            raise AdvisorError("flow_edges must be a list of at most 10000 edge pairs")
        edges, nodes = set(), set()
        for edge in flow_edges:
            if type(edge) not in (list, tuple) or len(edge) != 2:
                raise AdvisorError("each edge must be a [from, to] pair")
            source = _require_str("graph node", edge[0], 128)
            sink = _require_str("graph node", edge[1], 128)
            edges.add((source, sink))
            nodes.add(source)
            nodes.add(sink)
        if len(nodes) > MAX_NODES:
            raise AdvisorError("graph exceeds 5000 nodes")
        result = [list(edge) for edge in sorted(edges)]
        if len(_canonical(result)) > MAX_GRAPH_BYTES:
            raise AdvisorError("graph exceeds 1 MiB canonical edge bytes")
        return result

    @staticmethod
    def _path(source, sink, edges):
        adjacency = {}
        for a, b in edges:
            adjacency.setdefault(a, []).append(b)
        # BFS: shortest path, deterministic lexicographic neighbor tie breaking.
        pending = deque([source])
        parents = {source: None}
        while pending:
            node = pending.popleft()
            if node == sink and node != source:
                path = []
                while node is not None:
                    path.append(node)
                    node = parents[node]
                return list(reversed(path))
            for neighbor in sorted(adjacency.get(node, [])):
                if neighbor not in parents:
                    parents[neighbor] = node
                    pending.append(neighbor)
        return None

    def verify_reachability(self, alert_id, flow_edges, prerequisites_met,
                            remediation=None, coverage=None, *, graph_revision=None):
        """Assess a declared revision/graph; prerequisite values remain caller claims."""
        alert_id = _require_str("alert_id", alert_id, 128)
        graph_revision = _require_str("graph_revision", graph_revision)
        edges = self._validated_edges(flow_edges)
        prerequisites = _prerequisites(prerequisites_met)
        for name, value in (("remediation", remediation), ("coverage", coverage)):
            if value is not None:
                _require_str(name, value, 4096)
        with self._lock:
            self._require_integrity()
            if graph_revision != self._revision:
                raise AdvisorError("graph revision does not match this advisor")
            if alert_id not in self._alerts:
                raise AdvisorError("unknown alert")
            original = self._alerts[alert_id]
            required = original["required_prerequisites"]
            if required is not None and sorted(prerequisites) != required:
                raise AdvisorError("prerequisite names must exactly match the alert declaration")
            required = sorted(prerequisites) if required is None else list(required)
            path = self._path(original["source"], original["sink"], edges)
            unmet = [key for key, met in prerequisites.items() if not met]
            reachable = path is not None and not unmet
            if reachable and (remediation is None or coverage is None):
                raise AdvisorError("reachable findings require remediation and a coverage note")
            graph = {"schema": "l12/flow-graph/v2", "revision": graph_revision, "edges": edges}
            graph_size = len(_canonical(graph))
            prior_size = len(_canonical(self._graphs[alert_id])) if alert_id in self._graphs else 0
            prospective_bytes = self._graph_bytes - prior_size + graph_size
            if prospective_bytes > MAX_TOTAL_GRAPH_BYTES:
                raise AdvisorError("retained graphs exceed 8 MiB")
            assessment = {
                "schema": "l12/assessment/v2", "alert_id": alert_id,
                "tool": original["tool"], "rule": original["rule"],
                "source": original["source"], "sink": original["sink"],
                "affected_revision": self._revision, "graph_revision": graph_revision,
                "graph_digest": _digest(graph), "reachable_path": path,
                "prerequisites": prerequisites, "required_prerequisites": required,
                "prerequisite_claims_verified": False, "prerequisites_exhaustive_verified": False,
                "status": "GRAPH_REACHABLE" if reachable else "UNVERIFIED",
                "remediation": remediation, "verification_coverage": coverage,
                "coverage_executed": False, "vulnerability_verified": False,
            }
            if not reachable:
                assessment["reason"] = ("source-to-sink path not reachable on supplied graph"
                                        if path is None else "unmet prerequisites: " + ", ".join(unmet))
            assessment["assessment_digest"] = _digest(assessment)
            alert = dict(original, status=assessment["status"], required_prerequisites=required)
            if reachable:
                alert.pop("reason", None)
            else:
                alert["reason"] = assessment["reason"]
            prospective_alerts = dict(self._alerts, **{alert_id: alert})
            prospective_assessments = dict(self._assessments, **{alert_id: assessment})
            self._report_budget(prospective_alerts, prospective_assessments)
            self._alerts[alert_id] = alert
            self._assessments[alert_id] = assessment
            self._graphs[alert_id] = graph
            self._graph_bytes = prospective_bytes
            self._seal = self._state_hash()
            return copy.deepcopy(assessment)

    def _advisory_data(self, alerts, assessments):
        reachable, unverified = [], []
        for aid in sorted(alerts):
            entry = copy.deepcopy(assessments.get(aid, alerts[aid]))
            (reachable if entry["status"] == "GRAPH_REACHABLE" else unverified).append(entry)
        return {"schema": "l12/advisory/v2", "engine_version": VERSION,
                "revision": self._revision, "reachable_findings": reachable,
                "unverified_alerts": unverified,
                "counts": {"reachable": len(reachable), "unverified": len(unverified)},
                "gate_recommendation": "ADVISE_REVIEW" if alerts else "NOT_ASSESSED",
                "advisory_only": True, "human_decision_required": True,
                "source_analysis_performed": False, "merge_safety_assessed": False,
                "note": "A human reviewer must validate source, prerequisites, context and exploitability. Graph reachability is not a verified vulnerability."}

    def _report_budget(self, alerts, assessments):
        if len(_canonical(self._advisory_data(alerts, assessments))) + 256 > MAX_REPORT_BYTES:
            raise AdvisorError("prospective advisory exceeds 4 MiB")

    def advisory(self):
        with self._lock:
            self._require_integrity()
            report = self._advisory_data(self._alerts, self._assessments)
            report["state_digest"] = self._seal
            report["report_digest"] = _digest(report)
            return report

    def assessment(self, alert_id):
        """Detached current graph and assessment for review/recomputation."""
        alert_id = _require_str("alert_id", alert_id, 128)
        with self._lock:
            self._require_integrity()
            if alert_id not in self._assessments:
                raise AdvisorError("alert has no completed assessment")
            return {"assessment": copy.deepcopy(self._assessments[alert_id]),
                    "graph": copy.deepcopy(self._graphs[alert_id])}

    def verify(self):
        with self._lock:
            problems = self._problems()
            return {"schema": "l12/integrity/v2", "alerts": len(self._alerts),
                    "assessments": len(self._assessments), "retained_graph_bytes": self._graph_bytes,
                    "verdict": "FAIL" if problems else "PASS", "problems": problems}
