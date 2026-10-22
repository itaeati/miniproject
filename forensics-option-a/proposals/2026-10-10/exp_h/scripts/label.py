"""Mechanical attack labels for one evidence.db (evaluation only; never shown to a model).

Seeds come from the dataset's own ground-truth metadata (adversary_view): command-line substrings,
process ids, or artifact strings. Rules (generic Windows/Sysmon/Security field names only):
  1. seed processes: process-creation events whose command line contains a seed string, or the
     given (host, pid) pairs;
  2. descendants: every process created by an attack process (Sysmon 1 ParentProcessGuid/Id,
     Security 4688 creator ProcessId -> NewProcessId), to a fixpoint;
  3. an event is "lineage" when its acting process or its target process is an attack process
     (Sysmon: GUID; otherwise host + pid inside that process's lifetime);
  4. an event is "artifact" when its text contains an artifact string from the metadata;
  5. "ambiguous_target_only": the attack process is only the target and the actor is not an attack
     process (e.g. a system service opening it); excluded from both recall and FP rate;
  6. "near_unattributed": events with no acting process within near_seconds of an attack event on
     the same host (effects such as policy-change records); excluded from both recall and FP rate.
usage: label.py EVIDENCE_DB SPEC_JSON DATASET OUT_JSON
"""
import json
import re
import sqlite3
import sys
from collections import Counter

PS_CHANNELS = ("windows powershell", "microsoft-windows-powershell/operational")


def fields_of(full):
    out = {}
    for part in (full or "").split(" | "):
        if "=" in part:
            k, v = part.split("=", 1)
            out.setdefault(k.strip(), v.strip())
    return out


def pid(v):
    if v is None or str(v).strip() == "":
        return None
    s = str(v).strip()
    try:
        v = int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return None
    return v or None    # pid 0 = no process recorded


def hn(h):
    return (h or "").split(".")[0].lower()


def guid(v):
    return (v or "").strip("{} ").lower() or None


def main():
    db_path, spec_path, name, out_path = sys.argv[1:5]
    spec = json.load(open(spec_path))[name]
    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    evs = []
    for i, ts, ep, host, full in db.execute("select id, ts, ts_epoch, host, full from events order by ts_epoch, id"):
        f = fields_of(full)
        eid = str(f.get("EventID", ""))
        chan = (f.get("Channel") or f.get("SourceName") or "").lower()
        e = {"id": i, "ts": ts, "t": ep or 0.0, "host": hn(f.get("Hostname") or f.get("Computer") or host),
             "eid": eid, "chan": chan, "full": full or "", "f": f}
        # acting process
        e["a_guid"] = guid(f.get("SourceProcessGUID") or f.get("SourceProcessGuid") or f.get("ProcessGuid"))
        a = pid(f.get("SourceProcessId") or f.get("ProcessId") or f.get("ProcessID"))
        if a is None and chan.startswith(PS_CHANNELS):
            a = pid(f.get("ExecutionProcessID"))
        e["a_pid"] = a
        # target / created process
        e["t_guid"] = guid(f.get("TargetProcessGUID") or f.get("TargetProcessGuid"))
        e["t_pid"] = pid(f.get("TargetProcessId") or f.get("NewProcessId"))
        e["cmd"] = f.get("CommandLine") or f.get("ProcessCommandLine") or ""
        # creation: (new guid, new pid, parent guid, parent pid)
        e["create"] = None
        if "sysmon" in chan and eid == "1":
            e["create"] = (guid(f.get("ProcessGuid")), pid(f.get("ProcessId")), guid(f.get("ParentProcessGuid")),
                           pid(f.get("ParentProcessId")))
            e["a_guid"], e["a_pid"] = e["create"][0], e["create"][1]
        elif eid == "4688":
            e["create"] = (None, pid(f.get("NewProcessId")), None, pid(f.get("ProcessId")))
        e["exit"] = ("sysmon" in chan and eid == "5") or eid == "4689"
        evs.append(e)
    t_min = min(e["t"] for e in evs)
    t_max = max(e["t"] for e in evs)

    # process instances keyed by (host, pid, start); guid <-> pid mapping from Sysmon
    guid_pid = {}
    for e in evs:
        if e["a_guid"] and e["a_pid"] is not None:
            guid_pid.setdefault(e["a_guid"], (e["host"], e["a_pid"]))
        if e["create"] and e["create"][0] and e["create"][1] is not None:
            guid_pid[e["create"][0]] = (e["host"], e["create"][1])
    start = {}   # (host,pid) -> list of creation times
    end = {}     # (host,pid) -> list of exit times
    for e in evs:
        if e["create"] and e["create"][1] is not None:
            start.setdefault((e["host"], e["create"][1]), []).append(e["t"])
        if e["exit"] and e["a_pid"] is not None:
            end.setdefault((e["host"], e["a_pid"]), []).append(e["t"])

    def lifetime(hp, t_seen):
        """Lifetime of the instance of (host, pid) that is alive at t_seen."""
        s = max([x for x in start.get(hp, []) if x <= t_seen + 1.0], default=t_min)
        en = min([x for x in end.get(hp, []) if x >= t_seen - 1.0], default=t_max)
        return (s - 1.0, en + 1.0)

    att_guid, att_pid = set(), {}    # att_pid: (host,pid) -> list of (t0,t1)
    seeds = []

    def add(g, hp, t_seen, why):
        new = False
        if g and g not in att_guid:
            att_guid.add(g)
            new = True
            if g in guid_pid and hp is None:
                hp = guid_pid[g]
        if hp and hp[1] is not None:
            lt = lifetime(hp, t_seen)
            if lt not in att_pid.setdefault(hp, []):
                att_pid[hp].append(lt)
                new = True
        if new and why:
            seeds.append({"why": why, "guid": g, "host": hp[0] if hp else None, "pid": hp[1] if hp else None})
        return new

    subs = [s.lower() for s in spec.get("seed_cmd", [])]
    seed_pids = {(hn(h), p) for h, p in spec.get("seed_pid", [])}
    for e in evs:
        c = e["create"]
        if not c:
            continue
        hit_cmd = any(s in e["cmd"].lower() for s in subs)
        hit_pid = (e["host"], c[1]) in seed_pids
        if hit_cmd or hit_pid:
            add(c[0], (e["host"], c[1]), e["t"], f"seed E{e['id']}")
            if spec.get("include_parent"):
                add(c[2], (e["host"], c[3]), e["t"], f"seed parent E{e['id']}")
    for h, p in spec.get("seed_pid", []):
        hp = (hn(h), p)
        ts = [e["t"] for e in evs if e["host"] == hp[0] and (e["a_pid"] == p or e["t_pid"] == p)]
        for g in {e["a_guid"] for e in evs if e["host"] == hp[0] and e["a_pid"] == p and e["a_guid"]}:
            add(g, hp, min(ts) if ts else t_min, None)
        add(None, hp, min(ts) if ts else t_min, f"seed_pid {h}:{p}")

    def is_att(g, hp, t):
        if g and g in att_guid:
            return True
        if hp and hp[1] is not None and hp in att_pid:
            return any(t0 <= t <= t1 for t0, t1 in att_pid[hp])
        return False

    changed = True
    while changed:
        changed = False
        for e in evs:
            c = e["create"]
            if not c:
                continue
            if is_att(c[2], (e["host"], c[3]), e["t"]):
                if add(c[0], (e["host"], c[1]), e["t"], f"child E{e['id']}"):
                    changed = True
    arts = [s.lower() for s in spec.get("artifacts", [])]
    labels = {}
    for e in evs:
        why = []
        if is_att(e["a_guid"], (e["host"], e["a_pid"]), e["t"]):
            why.append("actor")
        if is_att(e["t_guid"], (e["host"], e["t_pid"]), e["t"]):
            why.append("target")
        low = e["full"].lower()
        hit = [a for a in arts if a in low]
        if hit:
            why.append("artifact:" + ",".join(hit))
        if why:
            labels[e["id"]] = why
    # a non-attack process acting on an attack process (e.g. a system service opening it): ambiguous
    ambiguous = {k: v for k, v in labels.items() if v == ["target"]}
    labels = {k: v for k, v in labels.items() if k not in ambiguous}
    att_times = {}
    for e in evs:
        if e["id"] in labels:
            att_times.setdefault(e["host"], []).append(e["t"])
    near = {}
    W = spec.get("near_seconds", 5.0)
    for e in evs:
        if e["id"] in labels or e["id"] in ambiguous or e["a_pid"] is not None or e["a_guid"]:
            continue
        if any(abs(e["t"] - t) <= W for t in att_times.get(e["host"], [])):
            near[e["id"]] = f"{e['chan'][:30]}:{e['eid']}"
    out = {"dataset": name, "events": len(evs), "attack_events": len(labels),
           "attack_share": round(len(labels) / len(evs), 4), "seed_trace": seeds[:200],
           "attack_processes": len(att_pid) + len(att_guid),
           "by_reason": dict(Counter(w.split(":")[0] for v in labels.values() for w in v)),
           "labels": {str(k): v for k, v in sorted(labels.items())},
           "ambiguous_target_only": sorted(ambiguous),
           "near_unattributed": {str(k): v for k, v in sorted(near.items())}, "spec": spec}
    json.dump(out, open(out_path, "w"), indent=1)
    print(f"{name:28s} events={len(evs):6d} attack={len(labels):5d} share={out['attack_share']:.3f} "
          f"ambiguous={len(ambiguous)} near={len(near)} procs={len(seeds)} reasons={out['by_reason']}")


if __name__ == "__main__":
    main()
