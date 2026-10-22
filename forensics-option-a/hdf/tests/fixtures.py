"""Synthetic evidence and a scripted stand-in for the LLM (no model server needed).
Values here exist only in test data; the engine and its prompts never contain them."""
from __future__ import annotations

import csv
import gzip
import json
import re
import zipfile
from pathlib import Path

from hdf.attack import Attack
from hdf.config import ModelConfig, load_config
from hdf.llm import ContextBudgetError, LLMError, LLMResult


def make_attack() -> Attack:
    techniques = {
        "T1059": {"name": "Command and Scripting Interpreter", "revoked_by": None, "deprecated": False},
        "T1059.001": {"name": "PowerShell", "revoked_by": None, "deprecated": False},
        "T1086": {"name": "PowerShell", "revoked_by": "T1059.001", "deprecated": False},
        "T1003.001": {"name": "LSASS Memory", "revoked_by": None, "deprecated": False},
        "T1071.001": {"name": "Web Protocols", "revoked_by": None, "deprecated": False},
        "T1110.001": {"name": "Password Guessing", "revoked_by": None, "deprecated": False},
        "T1043": {"name": "Commonly Used Port", "revoked_by": None, "deprecated": True},
    }
    return Attack(techniques, ["APT29", "Cozy Bear", "Fancy Bear"], ["Mimikatz", "Cobalt Strike"], "test")


def write_evidence(root: Path) -> Path:
    ev = root / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    rows = []
    # 300 routine process-access events: identical apart from PIDs/GUIDs -> one pattern
    for i in range(300):
        rows.append({"UtcTime": f"2021-03-04 10:{i // 60:02d}:{i % 60:02d}.{i % 1000:03d}", "Hostname": "WS1.corp.test",
                     "EventID": 10, "SourceImage": "C:\\Windows\\system32\\svchost.exe",
                     "TargetImage": "C:\\Windows\\system32\\services.exe", "GrantedAccess": "0x1000",
                     "SourceProcessId": 1000 + i, "SourceProcessGUID": f"{{6bbf237a-{i:04x}-5eac-1000-000000000{i % 10}00}}",
                     "Channel": "Microsoft-Windows-Sysmon/Operational"})
    # attack on WS1 (Sysmon UtcTime format: space separated, no zone)
    rows.append({"UtcTime": "2021-03-04 10:02:10.100", "Hostname": "WS1.corp.test", "EventID": 1,
                 "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                 "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0A",
                 "ParentImage": "C:\\Program Files\\Office\\winword.exe", "User": "CORP\\bob",
                 "Channel": "Microsoft-Windows-Sysmon/Operational"})
    rows.append({"UtcTime": "2021-03-04 10:02:12.500", "Hostname": "WS1.corp.test", "EventID": 3,
                 "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                 "DestinationIp": "203.0.113.50", "DestinationPort": 443, "User": "CORP\\bob",
                 "Channel": "Microsoft-Windows-Sysmon/Operational"})
    rows.append({"UtcTime": "2021-03-04 10:03:30.000", "Hostname": "WS1.corp.test", "EventID": 10,
                 "SourceImage": "C:\\Windows\\Temp\\pd.exe", "TargetImage": "C:\\Windows\\system32\\lsass.exe",
                 "GrantedAccess": "0x1fffff", "Channel": "Microsoft-Windows-Sysmon/Operational"})
    # security log on DC1 uses ISO-8601 with Z: must interleave correctly with the Sysmon events
    rows.append({"@timestamp": "2021-03-04T10:02:11.000Z", "Hostname": "DC1.corp.test", "EventID": 4624,
                 "TargetUserName": "bob", "LogonType": 3, "IpAddress": "10.0.0.5", "Channel": "Security"})
    rows.append({"@timestamp": "2021-03-04T10:04:00.000Z", "Hostname": "DC1.corp.test", "EventID": 4688,
                 "NewProcessName": "C:\\Windows\\System32\\ntdsutil.exe", "CommandLine": "ntdsutil \"ac i ntds\" ifm",
                 "Channel": "Security"})
    rows.append({"UtcTime": None, "Hostname": "WS1.corp.test", "EventID": 999, "Note": "event without timestamp"})
    with open(ev / "winlog.json", "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
        f.write("{not valid json\n")
    # syslog (year-less) gzipped
    with gzip.open(ev / "auth.log.1.gz", "wt") as f:
        for i in range(5):
            f.write(f"Mar  4 10:01:0{i} web01 sshd[{2000 + i}]: Failed password for root from 198.51.100.7 port {40000 + i} ssh2\n")
        f.write("Mar  4 10:01:09 web01 sshd[2010]: Accepted password for root from 198.51.100.7 port 40011 ssh2\n")
    # CloudTrail-style JSON document inside a zip
    ct = {"Records": [
        {"eventTime": "2021-03-04T10:05:00Z", "eventName": "GetObject", "sourceIPAddress": "198.51.100.7",
         "userIdentity": {"type": "IAMUser", "userName": "svc-backup"}, "requestParameters": {"bucketName": "finance-data"}},
        {"eventTime": "2021-03-04T10:05:30Z", "eventName": "ListBuckets", "sourceIPAddress": "198.51.100.7",
         "userIdentity": {"type": "IAMUser", "userName": "svc-backup"}}]}
    with zipfile.ZipFile(ev / "cloud.zip", "w") as z:
        z.writestr("trail/cloudtrail.json", json.dumps(ct))
    with open(ev / "proxy.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["time", "client", "url", "status"])
        w.writerow(["2021-03-04 10:02:13", "10.0.0.21", "https://203.0.113.50/beacon", "200"])
        w.writerow(["2021-03-04 10:02:43", "10.0.0.21", "https://203.0.113.50/beacon", "200"])
        w.writerow(["2021-03-04 10:02:50", "10.0.0.22", "https://intranet.corp.test/", "200"])
    (ev / "image.bin").write_bytes(b"\x00\x01\x02binary\x00" * 100)
    return ev


def make_config(tmp: Path, **over):
    o = {"paths": {"work_dir": str(tmp / "runs"), "attack_stix": str(tmp / "none.json")},
         "budget": {"context_tokens": 16384, "max_input_tokens": 3000, "max_output_tokens": 1000},
         "models": {"triage": {"name": "fake-triage", "path": str(tmp)},
                    "reasoner": {"name": "fake-reasoner", "path": str(tmp)}},
         "investigation": {"max_iterations": 3, "evidence_tokens": 1500}}
    for k, v in over.items():
        o.setdefault(k, {}).update(v)
    return load_config(None, o)


class FakeFormatter:
    def __init__(self, model: ModelConfig):
        self.model = model

    def format(self, system, user):
        return f"<s>{system}\n{user}\n<a>"

    def count(self, text):
        return len(text) // 3 + 1

    def count_many(self, texts):
        return [self.count(t) for t in texts]


class ScriptedClient:
    """Answers each phase with a callable chosen by request tag prefix."""

    def __init__(self, handlers: dict):
        self.handlers = handlers
        self.calls: list[tuple[str, str]] = []
        self._f = {}

    def formatter(self, model):
        return self._f.setdefault(model.role, FakeFormatter(model))

    def complete(self, model, system, user, tag, schema=None):
        self.calls.append((tag, user))
        self.schemas = getattr(self, "schemas", {})
        self.schemas[tag] = schema
        fmt = self.formatter(model)
        n = fmt.count(fmt.format(system, user))
        if n > model.max_input_tokens:
            raise ContextBudgetError(f"{n} > {model.max_input_tokens}")
        for prefix, fn in self.handlers.items():
            if tag.startswith(prefix):
                out = fn(user, tag)
                if isinstance(out, Exception):
                    raise out
                if not isinstance(out, str):
                    out = json.dumps(out)
                return LLMResult(out, out, n, len(out) // 3, False)
        raise LLMError(f"no handler for {tag}")


def p_ids_with(user: str, needle: str) -> list[str]:
    return [m.group(1) for m in re.finditer(r"^\[(P\d+)\][^\n]*" + re.escape(needle), user, re.M | re.I)]


def e_ids_with(user: str, needle: str) -> list[str]:
    return [m.group(1) for m in re.finditer(r"^\s*\[(E\d+)\]\*?[^\n]*" + re.escape(needle), user, re.M | re.I)]


def item_ids(user: str) -> list[str]:
    return re.findall(r"^\[([FL]\d+)\]", user, re.M)
