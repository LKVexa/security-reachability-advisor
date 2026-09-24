import unittest

from l12.core import AdvisorError, SecurityAdvisor

# taint flow: user_input -> parse -> query (sink); alt has a break
FLOW = [["user_input", "parse"], ["parse", "query"],
        ["other", "log"]]


def advisor():
    return SecurityAdvisor(revision="abc123")


class Alerts(unittest.TestCase):
    def test_revision_required(self):
        with self.assertRaises(AdvisorError):
            SecurityAdvisor("")

    def test_alert_is_not_a_vulnerability(self):
        a = advisor()
        r = a.record_alert("scanner-x", "SQLI", "user_input", "query")
        self.assertEqual(r["status"], "UNVERIFIED")
        adv = a.advisory()
        self.assertEqual(adv["counts"]["reachable"], 0)
        self.assertEqual(adv["counts"]["unverified"], 1)
        self.assertEqual(adv["gate_recommendation"], "ADVISE_REVIEW")


class Verification(unittest.TestCase):
    def setUp(self):
        self.a = advisor()
        self.aid = self.a.record_alert("scanner-x", "SQLI",
                                       "user_input", "query")["alert_id"]

    def test_reachable_with_prereqs_verifies(self):
        r = self.a.verify_reachability(
            self.aid, FLOW, {"input_untrusted": True},
            remediation="parameterize the query",
            coverage="unit + taint test added", graph_revision="abc123")
        self.assertEqual(r["status"], "GRAPH_REACHABLE")
        self.assertEqual(r["reachable_path"],
                         ["user_input", "parse", "query"])
        self.assertEqual(r["affected_revision"], "abc123")

    def test_unreachable_stays_unverified(self):
        r = self.a.verify_reachability(
            self.aid, [["user_input", "parse"]],   # no edge to query
            {"input_untrusted": True},
            remediation="x", coverage="y", graph_revision="abc123")
        self.assertEqual(r["status"], "UNVERIFIED")
        self.assertIn("not reachable", r["reason"])

    def test_unmet_prerequisite_stays_unverified(self):
        r = self.a.verify_reachability(
            self.aid, FLOW, {"input_untrusted": False},
            remediation="x", coverage="y", graph_revision="abc123")
        self.assertEqual(r["status"], "UNVERIFIED")
        self.assertIn("unmet prerequisites", r["reason"])

    def test_verified_requires_remediation_and_coverage(self):
        with self.assertRaises(AdvisorError):
            self.a.verify_reachability(self.aid, FLOW,
                                       {"input_untrusted": True}, graph_revision="abc123")

    def test_unknown_alert(self):
        with self.assertRaises(AdvisorError):
            self.a.verify_reachability("ghost", FLOW, {}, graph_revision="abc123")


class Advisory(unittest.TestCase):
    def setUp(self):
        self.a = advisor()

    def test_verified_advises_block_but_only_advises(self):
        aid = self.a.record_alert("s", "SQLI", "user_input",
                                  "query")["alert_id"]
        self.a.verify_reachability(aid, FLOW, {"input_untrusted": True},
                                   remediation="parameterize",
                                   coverage="taint test", graph_revision="abc123")
        adv = self.a.advisory()
        self.assertEqual(adv["gate_recommendation"], "ADVISE_REVIEW")
        self.assertTrue(adv["advisory_only"])
        self.assertTrue(adv["human_decision_required"])
        self.assertIn("human reviewer", adv["note"])
        v = adv["reachable_findings"][0]
        self.assertEqual(v["remediation"], "parameterize")
        self.assertTrue(v["assessment_digest"].startswith("sha256:"))

    def test_report_digest_deterministic(self):
        self.a.record_alert("s", "R", "a", "b")
        self.assertEqual(self.a.advisory()["report_digest"],
                         self.a.advisory()["report_digest"])

    def test_no_network_imports(self):
        import l12.core as m
        from pathlib import Path
        imports = " ".join(l for l in Path(m.__file__).read_text(encoding="utf-8").splitlines()
                           if l.startswith(("import ", "from ")))
        for bad in ("socket", "http", "urllib", "requests", "subprocess"):
            self.assertNotIn(bad, imports)


if __name__ == "__main__":
    unittest.main()

class HardeningV011(unittest.TestCase):
    """New tests for 0.1.1-partial fixes (A026-F1..F5)."""

    def setUp(self):
        self.a = advisor()
        self.aid = self.a.record_alert("s", "SQLI", "user_input",
                                       "query")["alert_id"]

    # F1 aliasing
    def test_advisory_report_is_not_aliased_to_internal_state(self):
        self.a.verify_reachability(self.aid, FLOW, {"p": True},
                                   remediation="f", coverage="c", graph_revision="abc123")
        adv = self.a.advisory()
        adv["reachable_findings"][0]["reachable_path"].append("EVIL")
        adv2 = self.a.advisory()
        self.assertEqual(adv2["reachable_findings"][0]
                         ["reachable_path"],
                         ["user_input", "parse", "query"])
        self.assertNotIn("EVIL", adv2["reachable_findings"][0]
                         ["reachable_path"])

    def test_verify_return_path_is_a_copy(self):
        r = self.a.verify_reachability(self.aid, FLOW, {"p": True},
                                       remediation="f", coverage="c", graph_revision="abc123")
        r["reachable_path"].append("EVIL")
        adv = self.a.advisory()
        self.assertEqual(adv["reachable_findings"][0]
                         ["reachable_path"],
                         ["user_input", "parse", "query"])

    # F2 error contract
    def test_malformed_edges_raise_advisor_error(self):
        from l12.core import AdvisorError
        for bad in (None, "notalist", [["a", "b", "c"]], [["a"]],
                    ["ab"], [["a", 3]], [["", "b"]]):
            with self.assertRaises(AdvisorError, msg=repr(bad)):
                self.a.verify_reachability(self.aid, bad, {},
                                           remediation="f", coverage="c", graph_revision="abc123")

    def test_non_dict_prerequisites_raise_advisor_error(self):
        with self.assertRaises(AdvisorError):
            self.a.verify_reachability(self.aid, FLOW, None,
                                       remediation="f", coverage="c", graph_revision="abc123")

    # F3 strict canonicalization / field validation
    def test_non_string_or_nan_alert_fields_rejected(self):
        for bad in (float("nan"), None, 5, object()):
            with self.assertRaises(AdvisorError, msg=repr(bad)):
                self.a.record_alert("t", bad, "s", "k")

    # F4 demotion strips stale verified evidence
    def test_demotion_strips_stale_verified_fields(self):
        self.a.verify_reachability(self.aid, FLOW, {"p": True},
                                   remediation="f", coverage="c", graph_revision="abc123")
        r = self.a.verify_reachability(self.aid, [["x", "y"]], {"p": True},
                                       remediation="f", coverage="c", graph_revision="abc123")
        self.assertEqual(r["status"], "UNVERIFIED")
        adv = self.a.advisory()
        self.assertEqual(adv["counts"]["reachable"], 0)
        st = self.a._alerts[self.aid]
        for stale in ("assessment_digest", "remediation",
                      "reachable_path", "verification_coverage"):
            self.assertNotIn(stale, st)

    def test_reverify_after_demotion_clears_reason(self):
        self.a.verify_reachability(self.aid, [["x", "y"]], {"p": True},
                                   remediation="f", coverage="c", graph_revision="abc123")
        r = self.a.verify_reachability(self.aid, FLOW, {"p": True},
                                       remediation="f", coverage="c", graph_revision="abc123")
        self.assertEqual(r["status"], "GRAPH_REACHABLE")
        self.assertNotIn("reason", self.a._alerts[self.aid])

    # F5 empty fields
    def test_empty_alert_fields_rejected(self):
        with self.assertRaises(AdvisorError):
            self.a.record_alert("", "", "", "")

    def test_non_string_revision_rejected(self):
        with self.assertRaises(AdvisorError):
            SecurityAdvisor(None)

    def test_version_constant(self):
        import l12.core as m
        self.assertEqual(m.VERSION, "0.1.2a1")
