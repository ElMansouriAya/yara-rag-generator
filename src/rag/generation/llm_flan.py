"""
Flan-T5-base wrapper — seq2seq architecture.
Lighter alternative to Qwen, good for benchmarking.
"""

import torch
from transformers import T5ForConditionalGeneration, T5Tokenizer
from src.rag.utils.config            import LLM_MODELS, MAX_NEW_TOKENS
from src.rag.generation.postprocessor import extract_yara_rule


class FlanLLM:
    name = "flan"

    def __init__(self):
        model_name     = LLM_MODELS["flan"]
        print(f"[FlanLLM] Loading {model_name}...")
        self.tokenizer = T5Tokenizer.from_pretrained(model_name)
        self.model     = T5ForConditionalGeneration.from_pretrained(
            model_name, torch_dtype=torch.float16, device_map="auto"
        )
        print(f"[FlanLLM] Ready")

    def generate(self, prompt: str, max_new_tokens: int = MAX_NEW_TOKENS) -> str:
        inputs  = self.tokenizer(
            prompt, return_tensors="pt", truncation=True, max_length=512
        ).to(self.model.device)
        outputs = self.model.generate(
            **inputs, max_new_tokens=max_new_tokens,
            num_beams=4, early_stopping=True
        )
        raw = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        return extract_yara_rule(raw)
