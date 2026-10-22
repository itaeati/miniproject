"""Phase-1 citation repair: a finding whose specific values are copied exactly from a
chunk line other than the one it cites is re-cited to that line and grounded again;
values found nowhere, or in too many lines, are not repaired."""
import tempfile
import unittest
from pathlib import Path

from hdf.grounding import Grounder
from hdf.ingest import Ingestor
from hdf.store import EvidenceStore
from hdf.triage import Triage
from hdf.util import read_jsonl

from .fixtures import ScriptedClient, make_attack, make_config, p_ids_with, write_evidence

EMPTY = {k: [] for k in ("hosts", "accounts", "processes", "command_lines", "files", "registry_keys", "ips",
                         "domains", "urls", "hashes", "other")}


class CitationRepairTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        ev = write_evidence(cls.tmp)
        cls.run_dir = cls.tmp / "run"
        cls.run_dir.mkdir()
        cls.cfg = make_config(cls.tmp)
        cls.store = EvidenceStore(cls.run_dir / "evidence.db", create=True)
        Ingestor(cls.cfg, cls.store, cls.run_dir).ingest([ev])
        attack = make_attack()
        cls.tri = Triage(cls.cfg, cls.store, ScriptedClient({}), cls.cfg.model("triage"), Grounder(attack), attack,
                         cls.run_dir)
        chunks, _ = cls.tri.plan()
        cls.c = next(c for c in chunks if p_ids_with(c.text, "ntdsutil"))

    def pid(self, needle):
        ids = p_ids_with(self.c.text, needle)
        self.assertEqual(len(ids), 1, needle)
        return ids[0]

    def ground(self, refs, **ents):
        obj = {"findings": [{"refs": refs, "severity": "high", "observation": "", "techniques": [],
                             "entities": {**EMPTY, **ents}}]}
        return self.tri._ground(self.c, obj)

    def test_wrong_line_is_re_cited(self):
        ntds, routine = self.pid("ntdsutil"), self.pid("services.exe")
        kept, rejected = self.ground([routine], command_lines=['ntdsutil "ac i ntds" ifm'],
                                     files=["C:\\Windows\\System32\\ntdsutil.exe"])
        self.assertEqual(len(kept), 1, rejected)
        f = kept[0]
        self.assertEqual([f"P{r}" for r in f["refs"]], [ntds])
        self.assertEqual(f["refs_repaired"]["from"], [routine])
        self.assertEqual(f["refs_repaired"]["to"], [ntds])
        self.assertEqual(f["entities"]["command_lines"], ['ntdsutil "ac i ntds" ifm'])
        self.assertEqual(rejected, [])
        audit = [r for r in read_jsonl(self.run_dir / "audit" / "rejections.jsonl")
                 if r.get("kind") == "refs_repaired_by_content"]
        self.assertTrue(any(r["to"] == [ntds] for r in audit))

    def test_invented_value_is_not_repaired(self):
        routine = self.pid("services.exe")
        kept, rejected = self.ground([routine], command_lines=["procdump.exe -ma lsass.exe out.dmp"])
        self.assertEqual(kept, [])
        kinds = [r["kind"] for r in rejected]
        self.assertIn("entity_not_in_cited_events:command_lines", kinds)
        self.assertIn("finding_without_verified_content", kinds)

    def test_value_in_many_lines_is_ambiguous(self):
        logon = self.pid("LogonType")  # the security-log line holds no Sysmon channel name
        kept, rejected = self.ground([logon], files=["Microsoft-Windows-Sysmon/Operational"])
        self.assertEqual(kept, [])
        self.assertIn("refs_repair_ambiguous", [r["kind"] for r in rejected])

    def test_correct_co_citation_is_kept(self):
        enc, net, routine = self.pid("-enc"), self.pid("203.0.113.50"), self.pid("services.exe")
        kept, rejected = self.ground([enc, routine], command_lines=["powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0A"],
                                     ips=["203.0.113.50"])
        self.assertEqual(len(kept), 1, rejected)
        self.assertEqual([f"P{r}" for r in kept[0]["refs"]], [enc, net])
        self.assertEqual(kept[0]["entities"]["ips"], ["203.0.113.50"])

    def test_report_lists_repairs_apart_from_rejections(self):
        from hdf.report import Reporter
        ntds, routine = self.pid("ntdsutil"), self.pid("services.exe")
        self.ground([routine], command_lines=['ntdsutil "ac i ntds" ifm'])
        rep = Reporter(self.cfg, self.store, None, self.cfg.model("reasoner"), self.tri.grounder, self.tri.attack,
                       self.run_dir)
        r = rep.build({"chunks_failed": []}, {"hypotheses": [], "errors": []}, [])
        self.assertGreaterEqual(r["audit"]["citations_repaired"], 1)
        self.assertNotIn("refs_repaired_by_content", r["audit"]["rejected_claims"])
        self.assertIn("re-cited to the line", (self.run_dir / "report.md").read_text())

    def test_correct_citation_untouched(self):
        ntds = self.pid("ntdsutil")
        kept, _ = self.ground([ntds], command_lines=['ntdsutil "ac i ntds" ifm'])
        self.assertNotIn("refs_repaired", kept[0])


if __name__ == "__main__":
    unittest.main()
