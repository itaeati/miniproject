"""Prompt templates. They describe forensic method only: no dataset values,
no example hosts, files, commands, dates or actor names (placeholders only)."""

PROMPT_VERSION = "hdf-prompts-1"

ENTITY_KEYS = ["hosts", "accounts", "processes", "command_lines", "files", "registry_keys",
               "ips", "domains", "urls", "hashes", "other"]
_ENTITIES_JSON = "{" + ", ".join(f'"{k}": []' for k in ENTITY_KEYS) + "}"

SYSTEM = (
    "You are a digital forensics and incident response (DFIR) analyst. You reason only from the evidence "
    "given in the request. You never add hosts, accounts, addresses, file names, commands, tools, malware or "
    "threat-actor names that are not written in that evidence. You answer with a single JSON object.")

TRIAGE = """Evidence source {label} (format: {fmt}).
Each line is one event pattern: identical activity that differs only in volatile values (process IDs, ports, GUIDs, counters).
Line format: [P<id>] <first time UTC> -> <last time UTC> x<count> hosts=<host(count), ...> :: <field=value | ...>
A line without a count is a single event. "..[+N chars]" marks a value shortened for display.
{constants}
=== EVIDENCE START ===
{lines}
=== EVIDENCE END ===

Task: identify activity in these lines that is suspicious or relevant to reconstructing an intrusion (initial access, execution, persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, collection, command and control, exfiltration, impact). Routine operating-system or software behaviour is not a finding.

Rules:
1. Base every finding only on the lines above and cite the P-ids of the lines used.
2. Copy entity values exactly as written in the cited lines.
3. Do not add hosts, accounts, addresses, files, commands, tools, malware or threat-actor names that are not written in the cited lines.
4. "techniques" may list MITRE ATT&CK technique IDs only when the cited lines directly show that behaviour.
5. If nothing is suspicious, return {{"findings": []}}.

Respond with one JSON object only:
{{"findings": [{{"refs": ["P<id>"], "severity": "high|medium|low", "observation": "<what the cited lines show>", "entities": {entities}, "techniques": []}}]}}"""

REDUCE = """The items below are verified findings (F-ids) or summaries of findings (L-ids) from one forensic investigation, in chronological order.
=== ITEMS START ===
{items}
=== ITEMS END ===

Task: merge related items into investigative leads (same activity chain, same host or account, consecutive steps of one operation).
Rules:
1. Every lead cites the item ids it summarises in "refs".
2. Every item that indicates suspicious activity must be cited by at least one lead.
3. Copy values exactly; do not add names or values that are not in the cited items.

Respond with one JSON object only:
{{"leads": [{{"refs": ["F<id>"], "severity": "high|medium|low", "summary": "<what the cited items show together>", "entities": {entities}, "techniques": []}}]}}"""

HYPOTHESIZE = """Evidence overview (computed from the evidence store):
{overview}

Verified findings and leads (chronological):
=== ITEMS START ===
{items}
=== ITEMS END ===
{context}
Task: propose up to {max_h} hypotheses that explain this activity as stages of an intrusion (how access was obtained, what was executed, persistence, privilege escalation, credential access, discovery, lateral movement, collection, exfiltration, command and control). Benign explanations may be proposed where the evidence allows them.
For each hypothesis, state the searches that would confirm or refute it. A search matches events containing ALL of its keywords (case-insensitive substrings) and can be limited to one host and a UTC time window.

Rules:
1. "refs" cites the item ids that motivate the hypothesis.
2. Entities and keywords must be copied exactly from the items or events shown above.
3. Do not name threat actors, malware families or tools unless the name is written in the evidence.
4. Do not repeat hypotheses listed as already supported or rejected.

Respond with one JSON object only:
{{"hypotheses": [{{"statement": "<hypothesis>", "refs": ["F<id>"], "techniques": [], "entities": {entities}, "queries": [{{"purpose": "<what it would confirm or refute>", "keywords": ["<exact string>"], "host": "", "time_from": "", "time_to": ""}}]}}]}}"""

EVALUATE = """Hypothesis: {statement}
Proposed ATT&CK techniques: {techniques}
Motivating findings:
{support}

Evidence retrieved from the full evidence store. Events are grouped by search; each search states how many events matched in total and which were sampled. Neighbouring events on the same host are included for context.
=== EVIDENCE START ===
{evidence}
=== EVIDENCE END ===

Task: decide whether the evidence SUPPORTS the hypothesis, REFUTES it, or is INSUFFICIENT.
- SUPPORTED: cited events directly show the claimed behaviour.
- REFUTED: cited events show the claim is false or the activity has a different explanation. Finding no matching events is INSUFFICIENT, not REFUTED.
- Cite E-ids for every conclusion. Copy values exactly.
- "confirmed_techniques": ATT&CK technique IDs whose behaviour the supporting events directly show.
- "new_pivots": concrete values in the evidence (addresses, accounts, files, processes, hosts, domains) worth searching across all evidence, each with the E-ids where it appears.
- "follow_up_queries": further searches that could resolve an INSUFFICIENT verdict.

Respond with one JSON object only:
{{"verdict": "SUPPORTED|REFUTED|INSUFFICIENT", "rationale": "<reasoning based on cited events>", "supporting_events": ["E<id>"], "refuting_events": ["E<id>"], "confirmed_techniques": [], "new_pivots": [{{"value": "<exact value>", "refs": ["E<id>"]}}], "follow_up_queries": [{{"purpose": "", "keywords": [], "host": "", "time_from": "", "time_to": ""}}]}}"""

NARRATIVE = """Verified conclusions of a forensic investigation, each with the events that support it:
=== FACTS START ===
{facts}
=== FACTS END ===

Task: write a concise incident summary of at most {n} sentences in chronological order, using only these facts.
Rules:
1. End every sentence with the E-ids that support it in square brackets.
2. Do not mention any value, name, time or conclusion that is not in the facts.
3. Do not attribute the activity to a threat actor, country or malware family.

Respond with one JSON object only:
{{"summary": ["<sentence> [E<id>, E<id>]"]}}"""


def entities_schema() -> str:
    return _ENTITIES_JSON
