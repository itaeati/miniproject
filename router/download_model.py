#!/usr/bin/env python3
"""
Download the fine-tuned network packet classification BERT model from Hugging Face
(rdpahalavan/bert-network-packet-flow-header-payload) and export it to ONNX format
(models/et_bert.onnx + models/et_bert.onnx.data).

Usage:
    pip install torch transformers onnx onnxscript
    python3 download_model.py
"""

import json
import os
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

MODEL_ID = "rdpahalavan/bert-network-packet-flow-header-payload"
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")


def main() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    print(f"[+] Downloading model and tokenizer: {MODEL_ID}")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_ID)
    model.eval()

    # Save vocabulary and label map
    vocab_src = tokenizer.save_vocabulary(OUT_DIR)[0]
    vocab_dst = os.path.join(OUT_DIR, "encryptd_vocab.txt")
    if vocab_src != vocab_dst and os.path.exists(vocab_src):
        os.replace(vocab_src, vocab_dst)

    labels_path = os.path.join(OUT_DIR, "labels.json")
    with open(labels_path, "w", encoding="utf-8") as f:
        json.dump(model.config.id2label, f, indent=2)
    print(f"[+] Saved label mapping ({len(model.config.id2label)} classes) -> {labels_path}")

    # Export to ONNX (seq_len = 128)
    dummy_ids = torch.ones(1, 128, dtype=torch.long)
    dummy_mask = torch.ones(1, 128, dtype=torch.long)
    onnx_path = os.path.join(OUT_DIR, "et_bert.onnx")

    print(f"[+] Exporting ONNX model -> {onnx_path}")
    torch.onnx.export(
        model,
        (dummy_ids, dummy_mask),
        onnx_path,
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        opset_version=14,
        do_constant_folding=True,
    )
    print("[+] Done! Generated models/et_bert.onnx and models/et_bert.onnx.data")


if __name__ == "__main__":
    main()
