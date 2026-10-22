import tempfile
import unittest
from pathlib import Path

from hdf.grounding import Grounder, extract_artifacts
from hdf.ingest import Ingestor, mask_text, residual_text
from hdf.llm import extract_json, strip_reasoning
from hdf.report import md_cell
from hdf.schemas import as_str_list, as_entities, as_refs, as_verdict
from hdf.store import EvidenceStore, norm_text
from hdf.timeparse import TimeParser, to_iso

from .fixtures import make_attack, make_config, write_evidence


class TimeParseTest(unittest.TestCase):
    def setUp(self):
        self.tp = TimeParser("UTC")

    def iso(self, v, **kw):
        dt, _ = self.tp.parse(v, **kw)
        return to_iso(dt) if dt else None

    def test_formats(self):
        self.assertEqual(self.iso("2020-05-02 02:55:23.551"), "2020-05-02T02:55:23.551Z")
        self.assertEqual(self.iso("2020-05-02T02:55:27.499Z"), "2020-05-02T02:55:27.499Z")
        self.assertEqual(self.iso("2020-05-02T02:55:27.4991234Z"), "2020-05-02T02:55:27.499Z")
        self.assertEqual(self.iso("2020-05-01T22:55:23-04:00"), "2020-05-02T02:55:23.000Z")
        self.assertEqual(self.iso("2020-05-01 22:55:23 +0900"), "2020-05-01T13:55:23.000Z")
        self.assertEqual(self.iso(1588388123), "2020-05-02T02:55:23.000Z")
        self.assertEqual(self.iso("1588388123551"), "2020-05-02T02:55:23.551Z")
        self.assertEqual(self.iso("02/May/2020:02:55:23 +0000"), "2020-05-02T02:55:23.000Z")
        self.assertEqual(self.iso("May  2 02:55:23", year_hint=2020), "2020-05-02T02:55:23.000Z")
        self.assertEqual(self.iso("5/2/2020 2:55:23 AM"), "2020-05-02T02:55:23.000Z")
        self.assertIsNone(self.iso("not a time"))
        self.assertIsNone(self.iso("12345"))
        self.assertIsNone(self.iso(None))

    def test_mixed_formats_sort_chronologically(self):
        # the old engine sorted these as strings and put every "T" timestamp after every " " timestamp
        a = self.tp.parse("2020-05-02 03:28:17.683")[0]
        b = self.tp.parse("2020-05-02T02:55:27.499Z")[0]
        self.assertLess(b, a)


class GroundingTest(unittest.TestCase):
    def setUp(self):
        self.g = Grounder(make_attack())
        self.hay = norm_text("Image=C:\\Windows\\System32\\cmd.exe | CommandLine=cmd.exe /c whoami | "
                             "DestinationIp=192.168.10.5 | User=CORP\\bob ts=2021-03-04T10:02:10.100Z")

    def test_extract(self):
        kinds = dict((v, k) for k, v in extract_artifacts(
            "cmd.exe connected to 6.6.6.6 and wrote C:\\Temp\\x.dll; key HKLM\\Software\\Run; acct CORP\\alice"))
        self.assertEqual(kinds.get("6.6.6.6"), "ipv4")
        self.assertIn("C:\\Temp\\x.dll", kinds)
        self.assertIn("cmd.exe", kinds)
        self.assertIn("CORP\\alice", kinds)

    def test_all_artifacts_required(self):
        # the old guard accepted a claim if ANY artifact matched
        r = self.g.check_text("cmd.exe exfiltrated the SAM hive to 6.6.6.6 using rclone.exe", self.hay)
        self.assertFalse(r.ok)
        self.assertIn("6.6.6.6", r.missing)
        self.assertIn("rclone.exe", r.missing)
        self.assertTrue(self.g.check_text("cmd.exe ran whoami and contacted 192.168.10.5", self.hay).ok)

    def test_actor_and_software_names(self):
        self.assertFalse(self.g.check_text("This matches APT29 tradecraft", self.hay).ok)
        self.assertFalse(self.g.check_text("Credentials were dumped with mimikatz", self.hay).ok)

    def test_times(self):
        self.assertTrue(self.g.check_text("At 10:02:10 cmd.exe ran", self.hay, ["2021-03-04T10:02:10.100Z"]).ok)
        self.assertFalse(self.g.check_text("At 11:45:00 cmd.exe ran", self.hay, ["2021-03-04T10:02:10.100Z"]).ok)


class ParsingTest(unittest.TestCase):
    def test_reasoning_and_json(self):
        self.assertEqual(strip_reasoning("thinking...</think>\n{\"a\":1}", True), ('{"a":1}', True))
        self.assertEqual(strip_reasoning("still thinking about {braces}", True), ("", False))
        raw = 'GUID {6bbf237a-cafb} looks odd</think>\n{"findings": [{"refs": ["P1"]}]}'
        ans, ok = strip_reasoning(raw, True)
        self.assertTrue(ok)
        self.assertEqual(extract_json(ans, "findings"), {"findings": [{"refs": ["P1"]}]})
        # braces before the JSON (the old greedy regex failed here)
        self.assertEqual(extract_json('note {x} then {"findings": []} end', "findings"), {"findings": []})
        self.assertIsNone(extract_json("no json", "findings"))
        # one finding is missing its closing brace: the complete ones are salvaged, nothing is invented
        broken = ('{"findings": [{"refs": ["P1"], "entities": {"x": []}, {"refs": ["P2"], "observation": "b"}, '
                  '{"refs": ["P3"], "observation": "c"}]}')
        self.assertIsNone(extract_json(broken, "findings"))
        sal = extract_json(broken, "findings", item_key="refs")
        self.assertEqual([f["refs"] for f in sal["findings"]], [["P2"], ["P3"]])
        self.assertTrue(sal["_salvaged"])
        # output cut off inside the second finding
        cut = '{"findings": [{"refs": ["P1"], "observation": "a"}, {"refs": ["P2"], "observ'
        self.assertEqual(extract_json(cut, "findings", item_key="refs")["findings"], [{"refs": ["P1"], "observation": "a"}])
        # reasoning channel delimited by special tokens (kept by the server on request)
        raw = '<|channel>thought\ndraft {"hypotheses": [{"statement": "draft"}]}<channel|>{"hypotheses": []}<turn|>'
        ans, ok = strip_reasoning(raw, False)
        self.assertTrue(ok)
        self.assertEqual(extract_json(ans, "hypotheses"), {"hypotheses": []})
        self.assertEqual(strip_reasoning('<|channel>thought\nstill drafting {"hypotheses": []}', False), ("", False))

    def test_coercion(self):
        self.assertEqual(as_verdict("SUPPORTED|REFUTED|INSUFFICIENT"), "INSUFFICIENT")
        self.assertEqual(as_verdict("supported"), "SUPPORTED")
        self.assertEqual(as_refs(["P12", "p13", 14, "[P15, P16]", None, {"x": 1}], "P"), [12, 13, 14, 15, 16])
        e = as_entities({"IPs": "1.2.3.4", "weird": [None, {"a": 1}, "x"], "hosts": 5})
        self.assertEqual(e["ips"], ["1.2.3.4"])
        self.assertEqual(e["other"], ["1", "x"])  # values inside objects are kept (and grounded later)
        self.assertEqual(e["hosts"], ["5"])
        self.assertEqual(as_entities("garbage")["ips"], [])
        # shapes produced by real models: objects instead of strings
        e = as_entities({"processes": [{"name": "a.exe"}, {"name": "b.exe", "pid": 7}], "accounts": {"name": "u1"}})
        self.assertEqual(e["processes"], ["a.exe", "b.exe"])
        self.assertEqual(e["accounts"], ["u1"])
        e = as_entities({"registry_keys": [{"key": "HKU\\S-1-5\\Software\\X", "action": "create"}]})
        self.assertEqual(e["registry_keys"], ["HKU\\S-1-5\\Software\\X"])
        techs = as_str_list([{"id": "T1059.001", "name": "PowerShell"}, "T1003.001", {"technique": {"id": "T1086"}}],
                            join_items=True)
        self.assertEqual(make_attack().clean_ids(techs), (["T1059.001", "T1003.001"], []))

    def test_attack(self):
        a = make_attack()
        self.assertEqual(a.canonical("T1086"), "T1059.001")
        self.assertIsNone(a.canonical("T1043"))
        self.assertIsNone(a.canonical("T9999"))
        ok, bad = a.clean_ids(["T1086", "T9999", "not a technique", "T1003.001"])
        self.assertEqual(ok, ["T1059.001", "T1003.001"])
        self.assertEqual(sorted(bad), ["T9999", "not a technique"])


class ClockAlignmentTest(unittest.TestCase):
    def ingest(self, rows):
        import json as _j
        tmp = Path(tempfile.mkdtemp())
        ev = tmp / "ev"
        ev.mkdir()
        (ev / "x.json").write_text("\n".join(_j.dumps(r) for r in rows) + "\n")
        store = EvidenceStore(tmp / "e.db", create=True)
        Ingestor(make_config(tmp), store, tmp / "run").ingest([ev])
        return store

    def test_consistent_offset_is_aligned(self):
        rows = [{"UtcTime": f"2020-10-18 23:50:{i:02d}.000", "TimeCreated": f"2020-10-18 07:50:{i:02d}.001",
                 "Hostname": "H", "Kind": "a"} for i in range(10)]
        rows += [{"TimeCreated": "2020-10-18 07:50:05.500", "Hostname": "H", "Kind": "b"}]
        st = self.ingest(rows)
        r = st.db.execute("SELECT ts, ts_quality FROM events WHERE full LIKE '%Kind=b%'").fetchone()
        self.assertEqual(r[1], "aligned")
        self.assertTrue(r[0].startswith("2020-10-18T23:50:05.4"), r[0])

    def test_inconsistent_offset_is_flagged(self):
        rows = [{"UtcTime": f"2020-10-18 23:50:{i:02d}.000", "TimeCreated": f"2020-10-18 0{i % 9}:50:00.000",
                 "Hostname": "H"} for i in range(10)]
        rows += [{"TimeCreated": "2020-10-18 07:50:05.500", "Hostname": "H", "Kind": "b"}]
        st = self.ingest(rows)
        r = st.db.execute("SELECT ts_quality FROM events WHERE full LIKE '%Kind=b%'").fetchone()
        self.assertEqual(r[0], "unaligned")


class IngestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.ev = write_evidence(cls.tmp)
        cls.run_dir = cls.tmp / "run"
        cls.run_dir.mkdir()
        cls.store = EvidenceStore(cls.run_dir / "evidence.db", create=True)
        cls.summary = Ingestor(make_config(cls.tmp), cls.store, cls.run_dir).ingest([cls.ev])

    def test_sources(self):
        by_name = {Path(s["path"]).name: s for s in self.summary["sources"]}
        self.assertEqual(by_name["winlog.json"]["fmt"], "jsonl")
        self.assertEqual(by_name["winlog.json"]["parse_errors"], 1)
        self.assertEqual(by_name["winlog.json"]["no_timestamp"], 2)  # bad line + event without time
        self.assertEqual(by_name["auth.log.1.gz"]["fmt"], "text")
        self.assertIn(by_name["cloudtrail.json"]["fmt"], ("json", "jsonl"))
        self.assertEqual(by_name["cloudtrail.json"]["events"], 2)
        self.assertEqual(by_name["proxy.csv"]["fmt"], "csv")
        self.assertEqual(by_name["image.bin"]["status"], "unsupported")

    def test_no_field_loss(self):
        ids, _ = self.store.search(["lsass.exe", "0x1fffff"])
        self.assertEqual(len(ids), 1)
        e = self.store.event(ids[0])
        self.assertIn("SourceImage=C:\\Windows\\Temp\\pd.exe", e.full)
        self.assertIn("GrantedAccess=0x1fffff", e.view)

    def test_cross_format_chronology(self):
        rows = list(self.store.db.execute(
            "SELECT host, ts FROM events WHERE ts BETWEEN '2021-03-04T10:02:09' AND '2021-03-04T10:02:13' "
            "ORDER BY ts_epoch"))
        hosts = [r[0] for r in rows]
        # DC1 logon (ISO Z) at 10:02:11 must sit between WS1 events at 10:02:10 and 10:02:12
        self.assertLess(hosts.index("WS1.corp.test"), hosts.index("DC1.corp.test"))
        self.assertTrue(any(r[0] == "WS1.corp.test" and r[1] > "2021-03-04T10:02:11" for r in rows))

    def test_patterns_group_noise_only(self):
        n_noise = self.store.db.execute(
            "SELECT COUNT(DISTINCT pattern) FROM events WHERE full LIKE '%services.exe%'").fetchone()[0]
        self.assertEqual(n_noise, 1)
        p_attack = self.store.db.execute(
            "SELECT COUNT(DISTINCT pattern) FROM events WHERE full LIKE '%lsass.exe%'").fetchone()[0]
        self.assertEqual(p_attack, 1)
        pats = self.store.db.execute("SELECT count FROM patterns ORDER BY count DESC").fetchall()
        self.assertEqual(pats[0][0], 300)

    def test_syslog_and_hosts(self):
        ids, n = self.store.search(["Failed password", "198.51.100.7"])
        self.assertEqual(n, 5)
        self.assertEqual(self.store.event(ids[0]).host, "web01")
        self.assertTrue(self.store.event(ids[0]).ts.endswith("10:01:00.000Z"))

    def test_search_filters_and_neighbors(self):
        ids, n = self.store.search(["powershell"], host="ws1.corp.test")
        self.assertEqual(n, 2)
        ids2, n2 = self.store.search(["powershell"], host="DC1.corp.test")
        self.assertEqual(n2, 0)
        nb = self.store.neighbors(ids[0], 2)
        evs = self.store.events(nb)
        self.assertTrue(all(e.host == "WS1.corp.test" for e in evs))
        self.assertEqual([e.ts_epoch for e in evs], sorted(e.ts_epoch for e in evs))

    def test_mask(self):
        self.assertEqual(mask_text("pid 1234 to 10.0.0.5 guid {6bbf237a-cafb-5eac-1000-000000000100}"),
                         "pid # to 10.0.0.5 guid <g>")


class MdCellTest(unittest.TestCase):
    def test_cut_never_leaves_a_dangling_escape(self):
        # the pipe sits exactly at the cut: escaping first used to leave "...+3c\\…"
        raw = "C:\\Windows\\a.dll+3c|C:\\b.dll"
        for limit in range(1, len(raw) + 2):
            cell = md_cell(raw, limit)
            back = cell.replace("\\|", "|").replace("…", "")  # as hdf.verify reads it
            self.assertTrue(raw.startswith(back), (limit, cell))
        self.assertEqual(md_cell("a|b", 10), "a\\|b")



class ResidualTextTest(unittest.TestCase):
    MSG = ("An attempt was made to access an object.\r\n\r\nSubject:\r\n\tAccount Name:\t\tuser1\r\n"
           "\tLogon ID:\t\t0xABC\r\n\r\nObject:\r\n\tObject Name:\t\t\\REGISTRY\\MACHINE\\X\r\n"
           "\tHandle ID:\t\t0x8f8\r\n\tTransaction ID:\t\t{00000000-0000-0000-0000-000000000000}\r\n"
           "\tProcess Name:\t\tC:\\Windows\\a.exe\r\n\r\nAccess Request Information:\r\n"
           "\tAccesses:\t\tREAD_CONTROL\r\n\t\t\t\tQuery key value\r\n\t\t\t\t\r\n"
           "\tAccess Reasons:\t\t-\r\n\tAccess Mask:\t\t0x20019\r\n\r\n"
           "Notes about this event.\r\nSecond line of the notes.")
    OTHERS = ["user1", "0xabc", "\\REGISTRY\\MACHINE\\X", "0x8f8", "C:\\Windows\\a.exe", "0x20019", "%%1538"]

    def test_keeps_only_what_other_fields_do_not_hold(self):
        r = residual_text(self.MSG, self.OTHERS)
        self.assertEqual(r.split(" \u21b5 "), ["An attempt was made to access an object.",
                                               "Accesses: READ_CONTROL Query key value",
                                               "Notes about this event.", "Second line of the notes."])

    def test_a_value_starting_with_a_drive_letter_is_not_a_label(self):
        r = residual_text("Process Command Line:\r\n\tC:\\x.exe -a\r\n", ["C:\\x.exe -a"])
        self.assertEqual(r, "")

    def test_values_held_by_other_fields_are_compared_whole_when_short(self):
        # "0" is a substring of many values but must match a whole value to count as held
        self.assertEqual(residual_text("Count:\t0\r\n", ["100"]), "Count: 0")
        self.assertEqual(residual_text("Count:\t0\r\n", ["0"]), "")


if __name__ == "__main__":
    unittest.main()
