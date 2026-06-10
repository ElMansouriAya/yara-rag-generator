"""
Mistral-7B-Instruct-v0.3 wrapper.
Uses 4-bit quantization (bitsandbytes) for Colab compatibility.
Requires: pip install bitsandbytes accelerate
"""

import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
from src.rag.utils.config            import LLM_MODELS, MAX_NEW_TOKENS, TEMPERATURE
from src.rag.generation.postprocessor import extract_yara_rule


class MistralLLM:
    name = "mistral"

    def __init__(self):
        model_name = LLM_MODELS["mistral"]
        print(f"[MistralLLM] Loading {model_name} in 4-bit...")

        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_use_double_quant=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.float16,
        )
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model     = AutoModelForCausalLM.from_pretrained(
            model_name,
            quantization_config=bnb_config,
            device_map="auto"
        )
        print(f"[MistralLLM] Ready (4-bit quantized)")

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
