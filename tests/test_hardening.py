from concurrent.futures import ThreadPoolExecutor
import copy
import itertools
import unittest
from unittest.mock import patch

import l12.core as core
from l12.core import SecurityAdvisor, AdvisorError, IntegrityError, _digest

FLOW = [["a", "b"], ["b", "z"]]


class Hardening(unittest.TestCase):
    def make(self, required=None, source="a", sink="z"):
        advisor = SecurityAdvisor("rev-1")
        aid = advisor.record_alert("scanner", "rule", source, sink, required)["alert_id"]
        return advisor, aid

    def assess(self, advisor, aid, edges=FLOW, prerequisites=None, **kwargs):
        return advisor.verify_reachability(
            aid, edges, {"p": True} if prerequisites is None else prerequisites,
            remediation="review and parameterize", coverage="caller says unit test",
            graph_revision="rev-1", **kwargs)

    def test_revision_is_readonly(self):
        advisor, _ = self.make()
        with self.assertRaises(AttributeError):
            advisor.revision = "other"
        self.assertEqual(advisor.revision, "rev-1")

    def test_text_validation(self):
        for value in (" ", "\ud800", "x\nx", "x"*257, 1, []):
            with self.assertRaises(AdvisorError):
                SecurityAdvisor(value)

    def test_node_size(self):
        with self.assertRaises(AdvisorError):
            self.make(source="界"*50)
        with self.assertRaises(AdvisorError):
            self.make(source="a", sink="a")

    def test_explicit_revision_required(self):
        advisor, aid = self.make()
        with self.assertRaises(AdvisorError):
            advisor.verify_reachability(aid, FLOW, {"p": True}, "fix", "tests")
        with self.assertRaises(AdvisorError):
            advisor.verify_reachability(aid, FLOW, {"p": True}, "fix", "tests", graph_revision="other")
        self.assertEqual(advisor.advisory()["counts"]["reachable"], 0)

    def test_no_auto_proceed(self):
        empty = SecurityAdvisor("rev-1").advisory()
        self.assertEqual(empty["gate_recommendation"], "NOT_ASSESSED")
        advisor, aid = self.make()
        self.assertEqual(advisor.advisory()["gate_recommendation"], "ADVISE_REVIEW")
        self.assess(advisor, aid, edges=[])
        self.assertEqual(advisor.advisory()["gate_recommendation"], "ADVISE_REVIEW")

    def test_reachability_not_vulnerability(self):
        advisor, aid = self.make()
        result = self.assess(advisor, aid)
        self.assertEqual(result["status"], "GRAPH_REACHABLE")
        self.assertFalse(result["vulnerability_verified"])
        self.assertFalse(result["coverage_executed"])
        self.assertFalse(result["prerequisite_claims_verified"])
        self.assertNotIn("verified_vulnerabilities", advisor.advisory())
        self.assertFalse(advisor.advisory()["merge_safety_assessed"])

    def test_truthy_prerequisites_refused(self):
        advisor, aid = self.make()
        for value in (1, "true", [], {}, None, 0.0):
            with self.assertRaises(AdvisorError):
                self.assess(advisor, aid, prerequisites={"p": value})

    def test_invalid_prerequisite_keys(self):
        advisor, aid = self.make()
        for value in ({1: True}, {"": True}, {"\ud800": True}, {"x"*129: True}):
            with self.assertRaises(AdvisorError):
                self.assess(advisor, aid, prerequisites=value)

    def test_all_inputs_validated_before_unreachable(self):
        advisor, aid = self.make()
        with self.assertRaises(AdvisorError):
            self.assess(advisor, aid, edges=[], prerequisites={"p": "yes"})
        self.assertEqual(advisor.verify()["assessments"], 0)

    def test_required_names_enforced(self):
        advisor, aid = self.make(required=["p", "q"])
        for prerequisites in ({"p": True}, {"p": True, "q": True, "r": True}, {}):
            with self.assertRaises(AdvisorError):
                self.assess(advisor, aid, prerequisites=prerequisites)
        self.assertEqual(self.assess(advisor, aid, prerequisites={"q": True, "p": True})["status"], "GRAPH_REACHABLE")

    def test_first_assessment_binds_names(self):
        advisor, aid = self.make()
        self.assess(advisor, aid)
        with self.assertRaises(AdvisorError):
            self.assess(advisor, aid, prerequisites={})
        self.assertEqual(advisor.advisory()["reachable_findings"][0]["required_prerequisites"], ["p"])

    def test_explicit_empty_prerequisites_are_not_exhaustiveness_proof(self):
        advisor, aid = self.make(required=[])
        result = self.assess(advisor, aid, prerequisites={})
        self.assertEqual(result["status"], "GRAPH_REACHABLE")
        self.assertFalse(result["prerequisites_exhaustive_verified"])

    def test_bad_declarations(self):
        for required in ("p", [1], ["p", "p"], [""]):
            with self.assertRaises(AdvisorError):
                self.make(required=required)

    def test_unmet_conditions_do_not_claim_nonexploitable(self):
        advisor, aid = self.make()
        result = self.assess(advisor, aid, prerequisites={"p": False})
        self.assertEqual(result["status"], "UNVERIFIED")
        self.assertEqual(result["reachable_path"], ["a", "b", "z"])
        self.assertNotIn("not exploitable", result["reason"])

    def test_shortest_path_selected(self):
        advisor, aid = self.make()
        edges = [["a", "b"], ["b", "c"], ["c", "z"], ["a", "z"]]
        self.assertEqual(self.assess(advisor, aid, edges=edges)["reachable_path"], ["a", "z"])

    def test_graph_order_duplicates_do_not_change_assessment(self):
        advisor, aid = self.make()
        edges = [["a", "c"], ["c", "z"], ["a", "b"], ["b", "z"]]
        first = self.assess(advisor, aid, edges=edges)
        second = self.assess(advisor, aid, edges=list(reversed(edges))+edges)
        self.assertEqual(first, second)
        self.assertEqual(first["reachable_path"], ["a", "b", "z"])

    def test_cycles_terminate(self):
        advisor, aid = self.make()
        result = self.assess(advisor, aid, edges=[["a", "b"], ["b", "a"], ["b", "z"], ["z", "z"]])
        self.assertEqual(result["reachable_path"], ["a", "b", "z"])

    def test_edge_direction_matters(self):
        advisor, aid = self.make()
        self.assertEqual(self.assess(advisor, aid, edges=[["z", "a"]])["status"], "UNVERIFIED")

    def test_all_small_directed_graphs(self):
        nodes = ["a", "b", "z"]
        possible = [(a, b) for a in nodes for b in nodes if a != b]
        for mask in range(1 << len(possible)):
            edges = [edge for i, edge in enumerate(possible) if mask & (1 << i)]
            closure = {a: {a} for a in nodes}
            for a, b in edges:
                closure[a].add(b)
            for _ in nodes:
                for a in nodes:
                    closure[a] |= set().union(*(closure[b] for b in list(closure[a])))
            path = SecurityAdvisor._path("a", "z", edges)
            self.assertEqual(path is not None, "z" in closure["a"])
            if path:
                self.assertTrue(all((a, b) in edges for a, b in zip(path, path[1:])))

    def test_long_chain_iterative(self):
        advisor, aid = self.make(source="n0", sink="n1500")
        edges = [[f"n{i}", f"n{i+1}"] for i in range(1500)]
        result = self.assess(advisor, aid, edges=edges)
        self.assertEqual(len(result["reachable_path"]), 1501)

    def test_graph_budgets(self):
        advisor, aid = self.make()
        for edges in ([["a", "z"]]*10001, [[f"n{i}", f"n{i+1}"] for i in range(5000)]):
            with self.assertRaises(AdvisorError):
                self.assess(advisor, aid, edges=edges)
        with patch("l12.core.MAX_GRAPH_BYTES", 1):
            with self.assertRaises(AdvisorError):
                self.assess(advisor, aid)

    def test_total_graph_budget_replaces_old(self):
        advisor, aid = self.make()
        self.assess(advisor, aid)
        size = advisor.verify()["retained_graph_bytes"]
        with patch("l12.core.MAX_TOTAL_GRAPH_BYTES", size):
            self.assess(advisor, aid)
            other = advisor.record_alert("s", "r", "a", "z")["alert_id"]
            with self.assertRaises(AdvisorError):
                self.assess(advisor, other)
        self.assertEqual(advisor.verify()["retained_graph_bytes"], size)

    def test_alert_limit_preserves_ids(self):
        advisor, _ = self.make()
        with patch("l12.core.MAX_ALERTS", 1):
            with self.assertRaises(AdvisorError):
                advisor.record_alert("s", "r", "a", "z")
        self.assertEqual(advisor.record_alert("s", "r", "a", "z")["alert_id"], "alert-0002")

    def test_report_capacity_refusal_atomic(self):
        advisor, aid = self.make()
        before = advisor.advisory()
        with patch("l12.core.MAX_REPORT_BYTES", 1):
            with self.assertRaises(AdvisorError):
                self.assess(advisor, aid)
            with self.assertRaises(AdvisorError):
                advisor.record_alert("s", "r", "a", "z")
        self.assertEqual(before, advisor.advisory())

    def test_remediation_coverage_bounds(self):
        advisor, aid = self.make()
        for value in (" ", "x"*4097, "\ud800", {}, 1):
            with self.assertRaises(AdvisorError):
                advisor.verify_reachability(aid, FLOW, {}, value, "tests", graph_revision="rev-1")

    def test_invalid_reassessment_preserves_previous(self):
        advisor, aid = self.make()
        self.assess(advisor, aid)
        before = advisor.advisory()
        with self.assertRaises(AdvisorError):
            self.assess(advisor, aid, prerequisites={"p": 1})
        self.assertEqual(before, advisor.advisory())

    def test_valid_demotion_replaces_evidence(self):
        advisor, aid = self.make()
        self.assess(advisor, aid)
        advisor.verify_reachability(aid, [], {"p": True}, graph_revision="rev-1")
        report = advisor.advisory()
        self.assertEqual(report["reachable_findings"], [])
        result = report["unverified_alerts"][0]
        self.assertIsNone(result["remediation"])
        self.assertIsNone(result["verification_coverage"])
        self.assertIsNone(result["reachable_path"])

    def test_all_evidence_bound_to_digest(self):
        advisor, aid = self.make()
        result = self.assess(advisor, aid)
        digest = result.pop("assessment_digest")
        self.assertEqual(digest, _digest(result))
        for key, value in (("tool", "other"), ("rule", "other"), ("remediation", "other"),
                           ("verification_coverage", "other"), ("prerequisites", {})):
            self.assertNotEqual(digest, _digest(dict(result, **{key: value})))

    def test_graph_export_digest(self):
        advisor, aid = self.make()
        self.assess(advisor, aid)
        exported = advisor.assessment(aid)
        self.assertEqual(exported["assessment"]["graph_digest"], _digest(exported["graph"]))

    def test_reports_graphs_and_input_detached(self):
        advisor, aid = self.make()
        edges = copy.deepcopy(FLOW)
        prerequisites = {"p": True}
        result = self.assess(advisor, aid, edges=edges, prerequisites=prerequisites)
        edges[0][0] = "evil"
        prerequisites["p"] = False
        result["reachable_path"].clear()
        exported = advisor.assessment(aid)
        exported["graph"]["edges"].clear()
        exported["assessment"]["prerequisites"].clear()
        self.assertEqual(advisor.assessment(aid)["graph"]["edges"], FLOW)
        self.assertEqual(advisor.verify()["verdict"], "PASS")

    def test_missing_assessment_export_refused(self):
        advisor, aid = self.make()
        with self.assertRaises(AdvisorError):
            advisor.assessment(aid)
        with self.assertRaises(AdvisorError):
            advisor.assessment("absent")

    def test_graph_and_assessment_tamper_fail_closed(self):
        for part in ("graph", "assessment", "alert", "revision"):
            advisor, aid = self.make()
            self.assess(advisor, aid)
            if part == "graph":
                advisor._graphs[aid]["edges"].clear()
            elif part == "assessment":
                advisor._assessments[aid]["remediation"] = "forged"
            elif part == "alert":
                advisor._alerts[aid]["tool"] = "forged"
            else:
                advisor._revision = "forged"
            self.assertEqual(advisor.verify()["verdict"], "FAIL")
            with self.assertRaises(IntegrityError):
                advisor.advisory()
            with self.assertRaises(IntegrityError):
                advisor.record_alert("s", "r", "a", "z")

    def test_removed_alert_detected(self):
        advisor, aid = self.make()
        advisor._alerts.clear()
        self.assertEqual(advisor.verify()["verdict"], "FAIL")

    def test_concurrent_record_ids(self):
        advisor = SecurityAdvisor("rev-1")
        with ThreadPoolExecutor(max_workers=8) as pool:
            ids = list(pool.map(lambda _: advisor.record_alert("s", "r", "a", "z")["alert_id"], range(40)))
        self.assertEqual(len(set(ids)), 40)
        self.assertEqual(advisor.advisory()["counts"]["unverified"], 40)

    def test_full_report_digest(self):
        advisor, aid = self.make()
        self.assess(advisor, aid)
        report = advisor.advisory()
        digest = report.pop("report_digest")
        self.assertEqual(digest, _digest(report))

    def test_prerequisite_declaration_detached(self):
        names = ["p"]
        advisor, aid = self.make(required=names)
        names.clear()
        with self.assertRaises(AdvisorError):
            self.assess(advisor, aid, prerequisites={})
