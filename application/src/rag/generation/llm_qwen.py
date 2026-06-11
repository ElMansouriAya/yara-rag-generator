"""
Qwen2.5-0.5B-Instruct wrapper.
Recommended for Google Colab free tier.
"""

import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
from src.rag.utils.config            import LLM_MODELS, MAX_NEW_TOKENS, TEMPERATURE
from src.rag.generation.postprocessor import extract_yara_rule


class QwenLLM:
    name = "qwen"

    def __init__(self):
        model_name     = LLM_MODELS["qwen"]
        print(f"[QwenLLM] Loading {model_name}...")
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model     = AutoModelForCausalLM.from_pretrained(
            model_name, torch_dtype=torch.float16, device_map="auto"
        )
        print(f"[QwenLLM] Ready")

    def generate(self, prompt: str, max_new_tokens: int = MAX_NEW_TOKENS) -> str:
        inputs  = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)
        outputs = self.model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=True,
            temperature=TEMPERATURE,
            pad_token_id=self.tokenizer.eos_token_id
        )
        raw = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        return extract_yara_rule(raw[len(prompt):].strip())
