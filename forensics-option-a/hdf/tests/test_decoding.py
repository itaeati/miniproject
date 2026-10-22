"""Decoding settings reach the server: each prompt's answer schema matches the JSON the
prompt asks for, the request body carries sampling / schema / repetition stop as the
model is configured, and a server that cannot honour them is refused."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

from hdf import output_schemas
from hdf.llm import LLMClient, LLMError, ServerManager
from hdf.prompts import EVALUATE, HYPOTHESIZE, NARRATIVE, REDUCE, TRIAGE, entities_schema

from .fixtures import FakeFormatter, make_config
from .test_memguard import FAKE_SERVER, GB, fake_meminfo, free_port


def example(template: str, **kw) -> dict:
    """The JSON object a prompt shows after 'Respond with one JSON object only:'."""
    text = template.format(**kw)
    return json.loads(text.split("Respond with one JSON object only:", 1)[1].strip())


def shape(schema: dict, obj) -> list[str]:
    """Differences between a schema's object keys and an example object, recursively."""
    out = []
    if isinstance(obj, dict):
        props = schema.get("properties", {})
        if set(props) != set(obj) or set(schema.get("required", [])) != set(obj):
            out.append(f"keys {sorted(props)} != {sorted(obj)}")
        for k in set(props) & set(obj):
            out += [f"{k}.{d}" for d in shape(props[k], obj[k])]
    elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
        out += shape(schema.get("items", {}), obj[0])
    return out


class SchemaMatchesPromptTest(unittest.TestCase):
    def test_every_prompt(self):
        e = entities_schema()
        cases = {
            "findings": (output_schemas.findings(), example(TRIAGE, label="", fmt="", constants="", lines="",
                                                            entities=e)),
            "leads": (output_schemas.leads(), example(REDUCE, items="", entities=e)),
            "hypotheses": (output_schemas.hypotheses(5, 4), example(HYPOTHESIZE, overview="", items="", context="",
                                                                    max_h=5, entities=e)),
            "verdict": (output_schemas.verdict(4), example(EVALUATE, statement="", techniques="", support="",
                                                           evidence="")),
            "summary": (output_schemas.summary(8), example(NARRATIVE, facts="", n=8)),
        }
        for name, (schema, ex) in cases.items():
            self.assertEqual(shape(schema, ex), [], name)

    def test_no_string_length_limit(self):
        # a maxLength made the grammar refuse backslash escapes (Windows paths)
        for s in (output_schemas.findings(), output_schemas.leads(), output_schemas.hypotheses(5, 4),
                  output_schemas.verdict(4), output_schemas.summary(8)):
            self.assertNotIn("maxLength", json.dumps(s))

    def test_limits_follow_config(self):
        h = output_schemas.hypotheses(3, 2)["properties"]["hypotheses"]
        self.assertEqual(h["maxItems"], 3)
        self.assertEqual(h["items"]["properties"]["queries"]["maxItems"], 2)
        self.assertEqual(output_schemas.summary(6)["properties"]["summary"]["maxItems"], 6)


class RequestBodyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "fake_server.py").write_text(FAKE_SERVER)

    def client(self, triage: dict, server: dict | None = None):
        models = {"triage": {"name": "fake-triage", "path": str(self.tmp), **triage},
                  "reasoner": {"name": "fake-reasoner", "path": str(self.tmp)}}
        cfg = make_config(self.tmp, models=models, server={
            "script": str(self.tmp / "fake_server.py"), "python": sys.executable, "port": free_port(),
            "startup_timeout_s": 30, "repetition_window_chars": 4000, "repetition_max_ratio": 0.1, **(server or {})})
        srv = ServerManager(cfg, self.tmp / "run")
        srv.meminfo_fn = lambda: fake_meminfo(12 * GB)
        self.addCleanup(srv.stop)
        cl = LLMClient(cfg, srv, self.tmp / "run" / "audit")
        model = cfg.model("triage")
        cl.formatters[model.role] = FakeFormatter(model)
        return cl, model

    def body(self):
        return json.loads((self.tmp / "last_body.json").read_text())

    def test_reasoning_model_with_model_sampling(self):
        cl, m = self.client({"enable_thinking": True, "sampling": "model", "structured_after": "</think>"})
        res = cl.complete(m, "s", "u", "t1", schema=output_schemas.findings())
        b = self.body()
        self.assertEqual(b["sampling"], "model")
        self.assertEqual(b["structured"], {"json_schema": output_schemas.findings(), "after": "</think>"})
        self.assertEqual(b["stop_on_repetition"], {"window_chars": 4000, "max_ratio": 0.1})
        self.assertEqual(res.finish, "stop")
        audit = json.loads(next((self.tmp / "run" / "audit").glob("*.json")).read_text())
        self.assertTrue(audit["structured"])
        self.assertEqual(audit["finish"], "stop")

    def test_thinking_off_schema_on_whole_answer(self):
        cl, m = self.client({"enable_thinking": False, "structured_after": "</think>"})
        cl.complete(m, "s", "u", "t1", schema=output_schemas.summary(8))
        b = self.body()
        self.assertNotIn("sampling", b)  # greedy
        self.assertEqual(b["structured"], {"json_schema": output_schemas.summary(8)})

    def test_structured_output_off(self):
        cl, m = self.client({"structured_output": False})
        cl.complete(m, "s", "u", "t1", schema=output_schemas.summary(8))
        self.assertNotIn("structured", self.body())

    def test_server_without_features_is_refused(self):
        (self.tmp / "no_caps").touch()
        cl, m = self.client({"sampling": "model"})
        with self.assertRaises(LLMError) as cm:
            cl.complete(m, "s", "u", "t1", schema=output_schemas.summary(8))
        self.assertIn("does not report structured_output, model_sampling, stop_on_repetition", str(cm.exception))
        self.assertFalse((self.tmp / "last_body.json").exists())


if __name__ == "__main__":
    unittest.main()
