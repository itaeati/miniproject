"""End-to-end tests with a scripted model: fabricated claims must never reach the report,
failures must be retried rather than cached, and the feedback loop must actually feed back."""
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from hdf.grounding import Grounder
from hdf.ingest import Ingestor
from hdf.investigate import Investigation
from hdf.llm import ContextBudgetError, LLMResult
from hdf.report import Reporter
from hdf.store import EvidenceStore
from hdf.triage import Triage
from hdf.util import read_json, read_jsonl
from hdf.verify import verify_run

from .fixtures import ScriptedClient, e_ids_with, item_ids, make_attack, make_config, p_ids_with, write_evidence


def triage_handler(user, tag):
    findings = []
    for p in p_ids_with(user, "lsass.exe"):
        findings.append({"refs": [p], "severity": "high",
                         "observation": "C:\\Windows\\Temp\\pd.exe opened lsass.exe with access 0x1fffff",
                         "entities": {"processes": ["C:\\Windows\\Temp\\pd.exe", "evil-c2.ru"], "ips": ["6.6.6.6"]},
                         "techniques": ["T1003.001", "T9999"]})
    for p in p_ids_with(user, "-enc"):
        findings.append({"refs": [p, "P999999"], "severity": "high",
                         "observation": "APT29 used powershell.exe to beacon to 203.0.113.50",
                         "entities": {"command_lines": ["powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0A"],
                                      "accounts": ["CORP\\bob"]},
                         "techniques": ["T1086"]})
    for p in p_ids_with(user, "203.0.113.50"):
        findings.append({"refs": [p], "severity": "medium", "observation": "outbound connection to 203.0.113.50",
                         "entities": {"ips": ["203.0.113.50"]}, "techniques": []})
    for p in p_ids_with(user, "Failed password"):
        findings.append({"refs": [p], "severity": "medium", "observation": "repeated failed SSH logins for root",
                         "entities": {"ips": ["198.51.100.7"], "accounts": ["root"]}, "techniques": ["T1110.001"]})
    for p in p_ids_with(user, "ntdsutil"):  # valid citation, but every claim about it is invented
        findings.append({"refs": [p], "severity": "medium", "observation": "C:\\Temp\\x.exe connected to 7.7.7.7",
                         "entities": {"processes": ["C:\\Temp\\x.exe"], "ips": ["7.7.7.7"]}, "techniques": []})
    findings.append({"refs": ["P424242"], "severity": "high", "observation": "invented", "entities": {}})
    return "reasoning about {braces} first</think>\n" + json.dumps({"findings": findings})


class Hyp:
    regen_prompts = []

    @classmethod
    def handler(cls, user, tag):
        items = item_ids(user)
        if "do not repeat" in user or "pivot values" in user:
            cls.regen_prompts.append(user)
            return {"hypotheses": [{"statement": "pd.exe was staged in C:\\Windows\\Temp before lsass.exe access",
                                    "refs": items[:1], "queries": [{"keywords": ["pd.exe"]}]}]}
        return {"hypotheses": [
            {"statement": "C:\\Windows\\Temp\\pd.exe read lsass.exe memory to dump credentials", "refs": items,
             "techniques": ["T1003.001"], "entities": {"processes": ["C:\\Windows\\Temp\\pd.exe", "mimikatz.exe"]},
             "queries": [{"purpose": "find access", "keywords": ["lsass.exe", "pd.exe"]}]},
            {"statement": "Data was exfiltrated to 6.6.6.6", "refs": items, "queries": [{"keywords": ["6.6.6.6"]}]},
            {"statement": "powershell.exe beaconed to 203.0.113.50", "refs": items, "techniques": ["T1071.001"],
             "queries": [{"keywords": ["203.0.113.50"], "host": "WS1.corp.test"}]},
            {"statement": "An account logged on to DC1.corp.test remotely", "refs": items,
             "queries": [{"keywords": ["4624", "LogonType=3"]}]},
            {"statement": "A scheduled task provided persistence", "refs": items,
             "queries": [{"keywords": ["no-such-string-xyz"]}]},
            {"statement": 5, "refs": "F1", "queries": "x"}, "not a dict", {"statement": None},
        ]}


def eval_handler(user, tag):
    st = re.search(r"^Hypothesis: (.*)$", user, re.M).group(1)
    if "staged" in st:  # echoes the verdict template instead of choosing
        return {"verdict": "REFUTED|SUPPORTED", "supporting_events": []}
    if "lsass" in st:
        ev = e_ids_with(user, "lsass.exe")
        return {"verdict": "SUPPORTED", "rationale": "event shows pd.exe opening lsass.exe",
                "supporting_events": ev, "confirmed_techniques": ["T1003.001"],
                "new_pivots": [{"value": "C:\\Windows\\Temp\\pd.exe", "refs": ev}, {"value": "9.9.9.9", "refs": ev}]}
    if "203.0.113.50" in st:
        return {"verdict": "SUPPORTED", "rationale": "connection observed",
                "supporting_events": e_ids_with(user, "203.0.113.50"), "confirmed_techniques": ["T1071.001"]}
    if "DC1" in st:  # claims support but cites an event it was never shown
        return {"verdict": "SUPPORTED", "supporting_events": ["E999999"]}
    return {"verdict": "REFUTED"}


def narrative_handler(user, tag):
    ev = e_ids_with(user, "lsass.exe")
    return {"summary": [
        f"C:\\Windows\\Temp\\pd.exe opened lsass.exe with access 0x1fffff [{ev[0]}]",
        f"This is consistent with APT29 tradecraft [{ev[0]}]",
        "The attacker then moved to 10.9.9.9 [E1]",
        "A sentence with no citation at all.",
    ]}


class PipelineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        ev = write_evidence(cls.tmp)
        cls.run_dir = cls.tmp / "run"
        cls.run_dir.mkdir()
        cls.cfg = make_config(cls.tmp)
        cls.store = EvidenceStore(cls.run_dir / "evidence.db", create=True)
        Ingestor(cls.cfg, cls.store, cls.run_dir).ingest([ev])
        cls.attack = make_attack()
        cls.g = Grounder(cls.attack)
        cls.client = ScriptedClient({"p1_": triage_handler, "p2_hypothesize": Hyp.handler,
                                     "p3_eval": eval_handler, "p4_narrative": narrative_handler,
                                     "p2_reduce": lambda u, t: {"leads": []}})
        cls.coverage = Triage(cls.cfg, cls.store, cls.client, cls.cfg.model("triage"), cls.g, cls.attack,
                              cls.run_dir).run()
        cls.findings = read_json(cls.run_dir / "findings.json")
        cls.state = Investigation(cls.cfg, cls.store, cls.client, cls.cfg.model("reasoner"), cls.g, cls.attack,
                                  cls.run_dir).run(cls.findings)
        cls.report = Reporter(cls.cfg, cls.store, cls.client, cls.cfg.model("reasoner"), cls.g, cls.attack,
                              cls.run_dir).build(cls.coverage, cls.state, cls.findings)
        cls.verification = verify_run(cls.run_dir, cls.attack)
        cls.rejections = read_jsonl(cls.run_dir / "audit" / "rejections.jsonl")

    def test_answer_schemas_sent(self):
        expect = {"p1_": "findings", "p2_reduce": "leads", "p2_hypothesize": "hypotheses", "p3_eval": "verdict",
                  "p4_narrative": "summary"}
        seen = set()
        for tag, schema in self.client.schemas.items():
            key = next(v for p, v in expect.items() if tag.startswith(p))
            self.assertIn(key, schema["required"], tag)
            seen.add(key)
        self.assertLessEqual({"findings", "hypotheses", "verdict", "summary"}, seen)

    def test_phase1_grounding(self):
        self.assertEqual(self.coverage["patterns_read"], self.coverage["patterns_total"])
        self.assertEqual(self.coverage["chunks_failed"], [])
        all_vals = json.dumps(self.findings)
        for fake in ("6.6.6.6", "evil-c2.ru", "APT29", "T9999", "P999999", "invented", "7.7.7.7", "x.exe"):
            self.assertNotIn(fake, all_vals)
        # a finding is kept only if its observation or at least one entity was verified
        for f in self.findings:
            self.assertTrue(f["observation"] or any(f["entities"].values()), f)
        ntds = [f for f in self.findings
                if any("ntdsutil" in self.store.norm_full(e) for e in f["events"])]
        self.assertEqual(ntds, [])
        lsass = [f for f in self.findings if "lsass" in (f.get("observation") or "")]
        self.assertEqual(len(lsass), 1)
        self.assertEqual(lsass[0]["entities"]["processes"], ["C:\\Windows\\Temp\\pd.exe"])
        self.assertEqual(lsass[0]["techniques"], ["T1003.001"])
        enc = [f for f in self.findings if any("-enc" in c for c in f["entities"]["command_lines"])]
        self.assertEqual(enc[0]["observation"], None)  # mentioned APT29 + an address not in the cited line
        self.assertEqual(enc[0]["techniques"], ["T1059.001"])  # revoked T1086 mapped
        kinds = {r["kind"].split(":")[0] for r in self.rejections}
        for k in ("entity_not_in_cited_events", "observation_unverified", "invalid_technique",
                  "ref_not_in_chunk", "finding_without_valid_refs", "finding_without_verified_content"):
            self.assertIn(k, kinds)

    def test_hypothesis_statuses(self):
        hyps = {h["statement"]: h for h in self.state["hypotheses"]}
        self.assertNotIn("Data was exfiltrated to 6.6.6.6", hyps)  # value not in evidence -> dropped
        lsass = hyps["C:\\Windows\\Temp\\pd.exe read lsass.exe memory to dump credentials"]
        self.assertEqual(lsass["status"], "SUPPORTED")
        self.assertNotIn("mimikatz.exe", json.dumps(lsass["entities"]))
        self.assertEqual(hyps["powershell.exe beaconed to 203.0.113.50"]["status"], "SUPPORTED")
        self.assertEqual(hyps["An account logged on to DC1.corp.test remotely"]["status"], "UNVERIFIED")
        sched = hyps["A scheduled task provided persistence"]
        self.assertEqual(sched["status"], "UNVERIFIED")  # no matches is never REFUTED
        self.assertEqual(sched["history"][0]["note"], "no matches")
        staged = [h for s, h in hyps.items() if "staged" in s]
        self.assertTrue(staged and staged[0]["status"] == "UNVERIFIED")

    def test_feedback_loop(self):
        self.assertTrue(Hyp.regen_prompts, "hypothesis generation was never re-run")
        p = Hyp.regen_prompts[0]
        self.assertIn("Hypotheses already supported", p)
        self.assertIn("pivot values", p)
        pivots = self.state["pivots"]
        self.assertIn("C:\\Windows\\Temp\\pd.exe", pivots)
        self.assertNotIn("9.9.9.9", pivots)
        self.assertTrue(pivots["C:\\Windows\\Temp\\pd.exe"]["searched"])
        self.assertTrue(self.state["pivot_events"])

    def test_report_contains_no_fabrication(self):
        md = (self.run_dir / "report.md").read_text()
        for fake in ("6.6.6.6", "10.9.9.9", "APT29", "mimikatz", "evil-c2.ru", "9.9.9.9", "scheduled task"):
            self.assertNotIn(fake.lower(), md.lower(), fake)
        self.assertEqual(len(self.report["conclusions"]), 2)
        self.assertEqual({t["id"] for t in self.report["techniques"]}, {"T1003.001", "T1071.001"})
        self.assertEqual(len(self.report["narrative"]), 1)
        self.assertEqual(self.report["audit"]["narrative_sentences_removed"], 3)
        self.assertTrue(self.verification["ok"], self.verification["violations"])

    def test_verifier_detects_tampering(self):
        tmp = Path(tempfile.mkdtemp())
        import shutil
        shutil.copytree(self.run_dir, tmp / "r", ignore=shutil.ignore_patterns("*.lock"))
        md = (tmp / "r" / "report.md").read_text().replace("## 3. Timeline",
                                                              "Data went to 6.6.6.6 via Cobalt Strike.\n\n## 3. Timeline")
        (tmp / "r" / "report.md").write_text(md)
        res = verify_run(tmp / "r", self.attack)
        self.assertFalse(res["ok"])
        self.assertTrue(any("6.6.6.6" in v for v in res["violations"]))
        self.assertTrue(any("Cobalt Strike" in v for v in res["violations"]))

    def test_unfinished_summary_is_reported(self):
        # the model counts event ids until the output limit (2026-10-08 run): the report says so
        run = Path(tempfile.mkdtemp()) / "run"
        shutil.copytree(self.run_dir, run)
        store = EvidenceStore(run / "evidence.db")
        loop = '{"summary": ["The account ran a command [' + ", ".join(f"E{i}" for i in range(1, 900))

        class CutOff(ScriptedClient):
            def complete(self, *a, **k):
                r = super().complete(*a, **k)
                return LLMResult(r.text, r.raw, r.prompt_tokens, 4096, True, "length")

        client = CutOff({"p4_narrative": lambda u, t: loop})
        rep = Reporter(self.cfg, store, client, self.cfg.model("reasoner"), Grounder(self.attack), self.attack,
                       run).build(self.coverage, self.state, self.findings)
        store.close()
        self.assertTrue(rep["conclusions"])
        self.assertEqual(rep["narrative"], [])
        note = "summary generation did not finish (finish=length, 4096 output tokens)"
        self.assertEqual(rep["narrative_note"], note)
        self.assertIn(f"(no summary: {note})", (run / "report.md").read_text())
        self.assertTrue(verify_run(run, self.attack)["ok"])


class FailureHandlingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        ev = write_evidence(self.tmp)
        self.run_dir = self.tmp / "run"
        self.run_dir.mkdir()
        self.cfg = make_config(self.tmp, triage={"max_split_depth": 1})
        self.store = EvidenceStore(self.run_dir / "evidence.db", create=True)
        Ingestor(self.cfg, self.store, self.run_dir).ingest([ev])
        self.attack = make_attack()

    def test_failures_are_not_cached_and_are_retried(self):
        bad = ScriptedClient({"p1_": lambda u, t: "</think> I cannot produce JSON"})
        tri = Triage(self.cfg, self.store, bad, self.cfg.model("triage"), Grounder(self.attack), self.attack,
                     self.run_dir)
        with self.assertRaises(RuntimeError):
            tri.run()
        statuses = [read_json(p)["status"] for p in (self.run_dir / "results" / "phase1").glob("*.json")]
        self.assertTrue(statuses and set(statuses) == {"failed"})
        good = ScriptedClient({"p1_": triage_handler})
        cov = Triage(self.cfg, self.store, good, self.cfg.model("triage"), Grounder(self.attack), self.attack,
                     self.run_dir).run()
        self.assertEqual(cov["chunks_failed"], [])
        self.assertTrue(good.calls, "failed chunks were not retried")
        self.assertTrue(read_json(self.run_dir / "findings.json"))
        # a successful result is reused on resume without new model calls
        again = ScriptedClient({"p1_": triage_handler})
        Triage(self.cfg, self.store, again, self.cfg.model("triage"), Grounder(self.attack), self.attack,
               self.run_dir).run()
        self.assertEqual(again.calls, [])

    def test_backend_memory_error_splits_chunk(self):
        def oom_for_big(user, tag):
            if user.count("\n[P") > 3:
                return ContextBudgetError("Exceeded max size of memory object allocation")
            return triage_handler(user, tag)
        c = ScriptedClient({"p1_": oom_for_big})
        cfg = make_config(self.tmp, triage={"max_split_depth": 6})
        cov = Triage(cfg, self.store, c, cfg.model("triage"), Grounder(self.attack), self.attack, self.run_dir).run()
        self.assertEqual(cov["chunks_failed"], [])
        self.assertTrue(any(".1" in t for t, _ in c.calls))

    def test_failed_hypothesis_generation_is_reported_not_hidden(self):
        c = ScriptedClient({"p1_": triage_handler, "p2_reduce": lambda u, t: {"leads": []},
                            "p2_hypothesize": lambda u, t: "thinking without an answer"})
        cov = Triage(self.cfg, self.store, c, self.cfg.model("triage"), Grounder(self.attack), self.attack,
                     self.run_dir).run()
        findings = read_json(self.run_dir / "findings.json")
        self.assertTrue(findings)
        state = Investigation(self.cfg, self.store, c, self.cfg.model("reasoner"), Grounder(self.attack),
                              self.attack, self.run_dir).run(findings)
        # the identical request is not sent again in the next iteration
        self.assertEqual(len([t for t, _ in c.calls if t.startswith("p2_hypothesize")]), 2)
        self.assertTrue(any(e["step"].startswith("p2_hypothesize") for e in state["errors"]))
        rep = Reporter(self.cfg, self.store, c, self.cfg.model("reasoner"), Grounder(self.attack), self.attack,
                       self.run_dir).build(cov, state, findings)
        self.assertEqual(rep["status"], "incomplete")
        self.assertTrue(any("p2_hypothesize" in p for p in rep["problems"]))
        self.assertIn("Status: INCOMPLETE", (self.run_dir / "report.md").read_text())

    def test_malformed_model_output_does_not_crash(self):
        weird = ScriptedClient({
            "p1_": lambda u, t: {"findings": [{"refs": p_ids_with(u, "lsass")[:1], "entities": ["x"],
                                               "observation": {"a": 1}, "severity": None, "techniques": 7},
                                              "string", None, {"refs": None}]},
            "p2_hypothesize": lambda u, t: {"hypotheses": {"statement": "lsass.exe accessed", "refs": "F1 F2",
                                                           "queries": [{"keywords": "lsass.exe", "time_from": "bad"}]}},
            "p3_eval": lambda u, t: {"verdict": None, "supporting_events": "E1", "new_pivots": "x",
                                     "follow_up_queries": 3},
            "p4_narrative": lambda u, t: {"summary": "plain string"},
            "p2_reduce": lambda u, t: {"leads": "nope"}})
        cov = Triage(self.cfg, self.store, weird, self.cfg.model("triage"), Grounder(self.attack), self.attack,
                     self.run_dir).run()
        findings = read_json(self.run_dir / "findings.json")
        state = Investigation(self.cfg, self.store, weird, self.cfg.model("reasoner"), Grounder(self.attack),
                              self.attack, self.run_dir).run(findings)
        rep = Reporter(self.cfg, self.store, weird, self.cfg.model("reasoner"), Grounder(self.attack), self.attack,
                       self.run_dir).build(cov, state, findings)
        self.assertEqual(rep["conclusions"], [])
        self.assertTrue(verify_run(self.run_dir, self.attack)["ok"])


if __name__ == "__main__":
    unittest.main()
