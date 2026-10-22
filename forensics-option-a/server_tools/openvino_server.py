#!/usr/bin/env python3
"""
OpenVINO GenAI High-Performance OpenAI-Compatible LLM Server
Target: Khadas Mind 2 (Intel Core Ultra 7 258V, Intel Arc Xe2 Graphics, XMX Hardware Acceleration)
"""

import os
import sys

# Auto-configure Intel Compute & Level Zero paths
os.environ["ZE_INTEL_ENABLE_ASYNC_FREE"] = "1"
INTEL_RUNTIME = "/home/ubuntu/intel-runtime"
LIB_PATHS = [
    f"{INTEL_RUNTIME}/usr/local/lib",
    f"{INTEL_RUNTIME}/usr/lib/x86_64-linux-gnu",
    f"{INTEL_RUNTIME}/usr/lib/x86_64-linux-gnu/intel-opencl",
    f"{sys.prefix}/lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages/openvino/libs"
]
curr_ld = os.environ.get("LD_LIBRARY_PATH", "")
os.environ["LD_LIBRARY_PATH"] = ":".join(LIB_PATHS) + (f":{curr_ld}" if curr_ld else "")
os.environ["OCL_ICD_VENDORS"] = f"{INTEL_RUNTIME}/etc/OpenCL/vendors"

import json
import re
import zlib
import time
import uuid
import argparse
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import openvino as ov
import openvino_genai as ov_genai
from transformers import AutoTokenizer

inference_lock = threading.Lock()
backend_adds_bos = False
bos_text = None
pipeline = None
tokenizer = None
model_name_id = "OpenVINO-LLM"
model_sampling = {}
device_name = "GPU"

def reset_vlm_pipeline_state(pipe):
    """Reset VLMContinuousBatchingAdapter / LLMPipeline chat & embedder state between requests."""
    if pipe is None:
        return
    if hasattr(pipe, "finish_chat"):
        try:
            pipe.finish_chat()
        except Exception:
            pass

class StreamerCallback:
    """Callback to stream tokens in real-time"""
    def __init__(self, wfile):
        self.wfile = wfile
        self.req_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
        self.created = int(time.time())

    def __call__(self, subword: str) -> bool:
        chunk = {
            "id": self.req_id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": model_name_id,
            "choices": [
                {
                    "index": 0,
                    "delta": {"content": subword},
                    "finish_reason": None
                }
            ]
        }
        data = f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"
        try:
            self.wfile.write(data.encode("utf-8"))
            self.wfile.flush()
            return False # Continue generation
        except (BrokenPipeError, ConnectionResetError):
            return True # Abort generation

class TokenCollector(ov_genai.StreamerBase):
    """Collects generated token ids so the text can be decoded with special tokens kept
    (reasoning-channel markers are special tokens and are dropped by the default decode).
    Optionally stops a degenerate repetition loop: every `check_every` tokens the last
    `window_chars` characters (digits masked, so counters do not hide a loop) are
    compressed; a ratio below `max_ratio` means the text is repeating itself."""
    def __init__(self, window_chars=0, max_ratio=0.0, check_every=32):
        super().__init__()
        self.ids = []
        self.window_chars, self.max_ratio, self.check_every = window_chars, max_ratio, check_every
        self.repetition = False

    def write(self, token):
        n = len(self.ids)
        if isinstance(token, int):
            self.ids.append(token)
        else:
            self.ids.extend(int(t) for t in token)
        if self.window_chars and len(self.ids) // self.check_every != n // self.check_every:
            # almost every token decodes to >= 1 character, so window_chars tokens fill the window;
            # window_chars // 2 did not for number-heavy text (~1.2 chars per token): no check ran
            tail = tokenizer.decode(self.ids[-self.window_chars:], skip_special_tokens=False)
            if len(tail) >= self.window_chars:
                w = re.sub(r"[0-9]", "#", tail[-self.window_chars:]).encode("utf-8")
                if len(zlib.compress(w, 9)) / len(w) < self.max_ratio:
                    self.repetition = True
                    return ov_genai.StreamingStatus.STOP
        return ov_genai.StreamingStatus.RUNNING

    def end(self):
        pass

class OpenVINORequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        # Concise logging
        sys.stderr.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {args[0]} {args[1]} {args[2]}\n")

    def _send_json(self, status, data_obj):
        if isinstance(data_obj, bytes):
            raw = data_obj
        else:
            raw = json.dumps(data_obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)
        self.wfile.flush()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Connection", "close")
        self.end_headers()

    def do_GET(self):
        if self.path in ["/health", "/"]:
            self._send_json(200, {
                "status": "ok",
                "backend": "OpenVINO GenAI",
                "device": device_name,
                "model": model_name_id,
                "raw_prompt": True,
                "keep_special_tokens": True,
                "structured_output": True,
                "stop_on_repetition": True,
                "model_sampling": bool(model_sampling)
            })
        elif self.path == "/v1/models":
            self._send_json(200, {
                "object": "list",
                "data": [
                    {
                        "id": model_name_id,
                        "object": "model",
                        "created": int(time.time()),
                        "owned_by": "openvino"
                    }
                ]
            })
        elif self.path in ["/slots", "/v1/slots"]:
            self._send_json(200, [{"id": 0, "state": 0, "n_ctx": 131072, "task_id": 0}])
        elif self.path in ["/v1/clear_cache", "/reset"] or "slots" in self.path:
            with inference_lock:
                reset_vlm_pipeline_state(pipeline)
                import gc, ctypes
                gc.collect()
                try:
                    ctypes.CDLL('libc.so.6').malloc_trim(0)
                except Exception:
                    pass
            self._send_json(200, {"status": "cleared"})
        else:
            self._send_json(404, {"error": "Not Found"})

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else ""

        if self.path in ["/v1/chat/completions", "/v1/completions", "/completion"]:
            try:
                data = json.loads(body) if body else {}
            except Exception as e:
                self._send_json(400, {"error": f"Invalid JSON: {e}"})
                return

            messages = data.get("messages", [])
            prompt_input = data.get("prompt", "")
            stream = data.get("stream", False)
            max_tokens = data.get("max_tokens", 2048)
            temperature = data.get("temperature", 0.7)
            top_p = data.get("top_p", 0.95)
            keep_special = data.get("skip_special_tokens", True) is False
            rep = data.get("stop_on_repetition") or {}

            # Build prompt
            if messages:
                if tokenizer and hasattr(tokenizer, "apply_chat_template"):
                    try:
                        formatted_prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
                    except Exception:
                        formatted_prompt = "\n".join([f"{m.get('role', 'user')}: {m.get('content', '')}" for m in messages])
                else:
                    formatted_prompt = "\n".join([f"{m.get('role', 'user')}: {m.get('content', '')}" for m in messages])
            else:
                formatted_prompt = prompt_input

            # The prompt is already fully formatted (chat template applied above for
            # "messages", or by the client for raw "prompt"). OpenVINO GenAI applies the
            # model's chat template again by default, which nests the whole prompt inside
            # a second user turn; disable that.
            if backend_adds_bos and bos_text and formatted_prompt.startswith(bos_text):
                formatted_prompt = formatted_prompt[len(bos_text):]
            config = ov_genai.GenerationConfig()
            config.apply_chat_template = False
            # Optional output constraint: a JSON schema, applied to the whole output or only to the
            # part after a reasoning end marker (e.g. "</think>"), so free-form reasoning stays allowed.
            structured = data.get("structured") or {}
            if structured.get("json_schema"):
                S = ov_genai.StructuredOutputConfig
                schema = structured["json_schema"]
                schema = schema if isinstance(schema, str) else json.dumps(schema)
                after = structured.get("after")
                if after:
                    config.structured_output_config = S(structural_tags_config=S.Concat(
                        S.Tag("", S.AnyText(), after), S.JSONSchema(schema)))
                else:
                    config.structured_output_config = S(json_schema=schema)
            config.max_new_tokens = max_tokens
            if data.get("sampling") == "model" and model_sampling:
                # the decoding settings shipped with the model (generation_config.json)
                for k, v in model_sampling.items():
                    setattr(config, k, v)
                if data.get("seed") is not None:
                    config.rng_seed = int(data["seed"])
            else:
                config.temperature = max(0.01, float(temperature))
                config.top_p = float(top_p)
            if data.get("stop_token_ids"):
                config.stop_token_ids = set(int(t) for t in data["stop_token_ids"])
            if data.get("stop_strings"):
                config.stop_strings = set(str(t) for t in data["stop_strings"])
                config.include_stop_str_in_output = True
            sampling_used = {"do_sample": config.do_sample, "temperature": config.temperature,
                             "top_p": config.top_p, "top_k": config.top_k if config.top_k < 2**31 else None,
                             "repetition_penalty": config.repetition_penalty, "rng_seed": config.rng_seed}

            req_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
            created_ts = int(time.time())

            if stream:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                
                streamer = StreamerCallback(self.wfile)
                try:
                    with inference_lock:
                        if is_vlm:
                            pipeline.generate(formatted_prompt, generation_config=config, streamer=streamer)
                        else:
                            pipeline.generate(formatted_prompt, config, streamer)
                except Exception as e:
                    sys.stderr.write(f"Streaming error: {e}\n")
                
                # Send terminal chunk
                term_chunk = {
                    "id": req_id,
                    "object": "chat.completion.chunk",
                    "created": created_ts,
                    "model": model_name_id,
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
                }
                self.wfile.write(f"data: {json.dumps(term_chunk, ensure_ascii=False)}\n\ndata: [DONE]\n\n".encode("utf-8"))
                self.wfile.flush()
            else:
                t0 = time.time()
                gen_ids = None
                collector = None
                try:
                    with inference_lock:
                        if keep_special and tokenizer is not None:
                            collector = TokenCollector(int(rep.get("window_chars") or 0),
                                                       float(rep.get("max_ratio") or 0.0))
                            if is_vlm:
                                pipeline.generate(formatted_prompt, generation_config=config, streamer=collector)
                            else:
                                pipeline.generate(formatted_prompt, config, collector)
                            gen_ids = collector.ids
                            res_text = tokenizer.decode(gen_ids, skip_special_tokens=False)
                        elif is_vlm:
                            raw_res = pipeline.generate(formatted_prompt, generation_config=config)
                            res_text = raw_res.texts[0] if hasattr(raw_res, "texts") and raw_res.texts else str(raw_res)
                        else:
                            res_text = pipeline.generate(formatted_prompt, config)
                    t_dur = time.time() - t0
                    is_rep = bool(collector is not None and collector.repetition)
                    n_gen = len(gen_ids) if gen_ids is not None else None
                    reset_vlm_pipeline_state(pipeline)
                    collector = None
                    gen_ids = None
                    import gc, ctypes
                    gc.collect()
                    try:
                        ctypes.CDLL('libc.so.6').malloc_trim(0)
                    except Exception:
                        pass
                except Exception as e:
                    import traceback
                    sys.stderr.write(f"Inference exception: {traceback.format_exc()}\n")
                    self._send_json(500, {"error": f"Inference failed: {e}"})
                    return

                res_json = {
                    "id": req_id,
                    "object": "chat.completion",
                    "created": created_ts,
                    "model": model_name_id,
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": res_text
                            },
                            "text": res_text,
                            "finish_reason": ("repetition" if is_rep else
                                              "length" if n_gen is not None and n_gen >= max_tokens else "stop")
                        }
                    ],
                    "usage": {
                        "prompt_tokens": len(tokenizer(formatted_prompt).input_ids) if tokenizer else len(formatted_prompt)//4,
                        "completion_tokens": n_gen if n_gen is not None else (len(tokenizer(res_text).input_ids) if tokenizer else len(res_text)//4),
                        "total_tokens": 0
                    }
                }
                res_json["usage"]["total_tokens"] = res_json["usage"]["prompt_tokens"] + res_json["usage"]["completion_tokens"]
                res_json["usage"]["seconds"] = round(t_dur, 2)
                res_json["sampling_used"] = sampling_used
                self._send_json(200, res_json)
                try:
                    import ctypes, gc
                    gc.collect()
                    ctypes.CDLL('libc.so.6').malloc_trim(0)
                except Exception:
                    pass
        elif self.path in ['/v1/clear_cache', '/reset'] or 'slots' in self.path:
            with inference_lock:
                reset_vlm_pipeline_state(pipeline)
                import gc, ctypes
                gc.collect()
                try:
                    ctypes.CDLL('libc.so.6').malloc_trim(0)
                except Exception:
                    pass
            self._send_json(200, {"status": "cleared", "slot_id": 0})
        else:
            self._send_json(404, {"error": "Not Found"})

def main():
    global pipeline, tokenizer, model_name_id, device_name, is_vlm, backend_adds_bos, bos_text, model_sampling
    
    parser = argparse.ArgumentParser(description="OpenVINO LLM OpenAI Server")
    parser.add_argument("--model-path", "-m", type=str, default="/home/ubuntu/llama-models/FoundationSec-8B-OV-INT4", help="Path to OpenVINO IR model directory")
    parser.add_argument("--device", "-d", type=str, default="GPU", choices=["GPU", "NPU", "CPU"], help="Inference device")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host address")
    parser.add_argument("--port", "-p", type=int, default=8081, help="Port number")
    args = parser.parse_args()

    device_name = args.device
    model_name_id = os.path.basename(args.model_path.rstrip("/"))

    print(f"🚀 Initializing OpenVINO GenAI on {device_name}...")
    print(f"📁 Model Directory: {args.model_path}")
    
    t0 = time.time()
    core = ov.Core()
    print(f"✔ Available OpenVINO Devices: {core.available_devices}")

    scheduler = ov_genai.SchedulerConfig()
    scheduler.cache_size = 4
    scheduler.max_num_seqs = 1
    scheduler.enable_prefix_caching = False

    is_vlm = os.path.exists(os.path.join(args.model_path, "openvino_language_model.xml"))
    if is_vlm:
        print("✔ Multimodal / VLM architecture detected. Loading VLMPipeline...")
        vlm_scheduler = ov_genai.SchedulerConfig()
        vlm_scheduler.max_num_batched_tokens = (1 << 64) - 1
        vlm_scheduler.enable_prefix_caching = False
        pipeline = ov_genai.VLMPipeline(args.model_path, device_name, scheduler_config=vlm_scheduler)
    else:
        print("✔ Standard LLM architecture detected. Loading LLMPipeline with PagedAttention SchedulerConfig...")
        pipeline = ov_genai.LLMPipeline(args.model_path, device_name, scheduler_config=scheduler)

    try:
        tokenizer = AutoTokenizer.from_pretrained(args.model_path)
    except Exception as e:
        print(f"Notice: Standard tokenizer fallback: {e}")
        tokenizer = None
        
    try:
        bos_text = tokenizer.bos_token if tokenizer is not None else None
        bos_id = tokenizer.bos_token_id if tokenizer is not None else None
        probe = pipeline.get_tokenizer().encode("a").input_ids.data[0]
        backend_adds_bos = bool(bos_id is not None and len(probe) and int(probe[0]) == int(bos_id))
    except Exception as e:
        print(f"Notice: BOS probe failed: {e}")
        backend_adds_bos = False
    print(f"✔ Backend tokenizer adds BOS: {backend_adds_bos} (bos={bos_text!r})")
    print(f"✔ Model loaded successfully in {time.time() - t0:.2f}s")
    try:
        with open(os.path.join(args.model_path, "generation_config.json")) as f:
            gc = json.load(f)
        model_sampling = {k: gc[k] for k in ("do_sample", "temperature", "top_k", "top_p", "repetition_penalty", "min_p")
                          if k in gc}
    except (OSError, ValueError) as e:
        print(f"Notice: no generation_config.json sampling defaults: {e}")
        model_sampling = {}
    print(f"✔ Model sampling defaults: {model_sampling}", flush=True)
    
    server_addr = (args.host, args.port)
    httpd = ThreadingHTTPServer(server_addr, OpenVINORequestHandler)
    print(f"🔥 OpenVINO LLM Server listening on http://{args.host}:{args.port}")
    print(f"✔ OpenAI Endpoint: http://{args.host}:{args.port}/v1/chat/completions")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping OpenVINO LLM server...")
        httpd.server_close()

if __name__ == "__main__":
    main()
