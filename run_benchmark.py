"""
run_benchmark.py — Complete benchmark script for YARA RAG System.

Tests all modes (baseline, classic, hybrid, agentic) across all models
(Qwen, Mistral, Flan-T5) and produces a full report.

Usage (VS Code terminal):
    python run_benchmark.py                    # Qwen only (fast)
    python run_benchmark.py --models all       # all 3 models
    python run_benchmark.py --models qwen flan # specific models
    python run_benchmark.py --output results/  # custom output dir

Output:
    results/benchmark_results.json    ← full raw results
    results/benchmark_summary.csv     ← metrics table (Excel-friendly)
    results/benchmark_report.txt      ← human-readable report
"""

import os
import sys
import json
import argparse
import datetime
import pandas as pd
from pathlib import Path

# ── Path setup ───────────────────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from src.rag.kb.knowledge_base      import KnowledgeBase
from src.rag.pipeline.pipeline      import YARAPipeline
from src.rag.evaluation.metrics     import evaluate_result, average_metrics
from src.rag.evaluation.yara_validator import validate

# ── Test queries + references ────────────────────────────────────────────────
# run_benchmark.py — LIGNES 28-55 (TEST_QUERIES + REFERENCES)

TEST_QUERIES = [
    "LockBit ransomware encrypting files with AES-256 and deleting shadow copies via vssadmin",
    "WannaCry ransomworm exploiting EternalBlue MS17-010 for lateral movement and file encryption",
    "QuasarRAT trojan with keylogging and screenshot capture exfiltrating via FTP",
    "CobaltStrike beacon using DNS tunneling for command and control communication",
    "XMRig cryptominer connecting to stratum+tcp pool for Monero mining",
    "Dridex banking trojan injecting code into browser to steal credentials from login pages",
    "Mimikatz tool harvesting credentials from LSASS memory and Windows registry",
    "Worm propagating through SMB network shares and NetShareEnum for lateral movement",
    "Spyware using BitBlt for screenshots and InternetOpenUrl for HTTP exfiltration",
    "Dropper disguised as PDF document using WinExec to download remote payload",
]

REFERENCES = [
    'rule LockBit_Ransomware { meta: description="LockBit ransomware" strings: $aes="AES-256" nocase $vss="vssadmin delete shadows" nocase condition: $aes and $vss }',
    'rule WannaCry_Ransomworm { meta: description="WannaCry" strings: $smb="MS17-010" nocase $svc="mssecsvc.exe" nocase $ext=".wncry" nocase condition: 2 of them }',
    'rule QuasarRAT_Trojan { meta: description="QuasarRAT" strings: $keylog="SetWindowsHookEx" nocase $ftp="FtpPutFile" nocase $screen="BitBlt" nocase condition: 2 of them }',
    'rule CobaltStrike_DNS { meta: description="CobaltStrike DNS beacon" strings: $dns="DnsQuery" nocase $b64="base64" nocase $beacon="beacon" nocase condition: $dns and $beacon }',
    'rule XMRig_Miner { meta: description="XMRig miner" strings: $xmr="xmrig" nocase $stratum="stratum+tcp://" nocase condition: $xmr or $stratum }',
    'rule Dridex_Banker { meta: description="Dridex banking trojan" strings: $inject="CreateRemoteThread" nocase $login="login.php" nocase condition: $inject and $login }',
    'rule Mimikatz_Credential { meta: description="Mimikatz credential harvester" strings: $lsass="sekurlsa" nocase $reg="HKEY_LOCAL_MACHINE" nocase condition: $lsass or $reg }',
    'rule SMB_Worm { meta: description="SMB worm" strings: $smb="NetShareEnum" nocase $admin="ADMIN$" nocase condition: 2 of them }',
    'rule Screenshot_Spy { meta: description="Screenshot spyware" strings: $blt="BitBlt" nocase $http="InternetOpenUrl" nocase condition: $blt and $http }',
    'rule Fake_PDF_Drop { meta: description="Fake PDF dropper" strings: $pdf="%PDF" nocase $exec="WinExec" nocase condition: $pdf and $exec }',
]

MODES   = ["classic", "hybrid", "agentic"]
MODELS  = {
    "qwen"   : "src.rag.generation.llm_qwen.QwenLLM",
    "mistral": "src.rag.generation.llm_mistral.MistralLLM",
    "flan"   : "src.rag.generation.llm_flan.FlanLLM",
}


# ── Helpers ──────────────────────────────────────────────────────────────────

def load_llm(model_name: str):
    """Dynamically load an LLM by name."""
    import importlib
    module_path, class_name = MODELS[model_name].rsplit(".", 1)
    module = importlib.import_module(module_path)
    cls    = getattr(module, class_name)
    return cls()


def print_rule_box(query: str, rule: str, mode: str):
    """Pretty-print a generated YARA rule."""
    print(f"\n  {'─'*60}")
    print(f"  Query  : {query[:70]}...")
    print(f"  Mode   : {mode}")
    print(f"  {'─'*60}")
    for line in rule.strip().split("\n"):
        print(f"  {line}")
    print(f"  {'─'*60}")


def format_metrics(m: dict) -> str:
    """Format metrics dict as a compact string."""
    return (
        f"BLEU={m.get('bleu',0):.3f} "
        f"ROUGE-L={m.get('rouge_l',0):.3f} "
        f"SemSim={m.get('semantic_similarity',0):.3f} "
        f"Valid={m.get('yara_valid',0)} "
        f"Syntax={m.get('syntax_score',0):.2f} "
        f"Hallu={m.get('hallucination_score',0):.2f} "
        f"P@k={m.get('precision_at_k',0):.2f} "
        f"MRR={m.get('mrr',0):.2f}"
    )


# ── Core benchmark function ──────────────────────────────────────────────────

def run_benchmark(
    model_names : list[str],
    output_dir  : str = "results",
    verbose     : bool = True
) -> dict:
    """
    Run full benchmark across models and modes.

    Returns:
        dict with all_results and summary tables
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    print("\n" + "="*70)
    print("  YARA RAG SYSTEM — FULL BENCHMARK")
    print(f"  Models : {model_names}")
    print(f"  Modes  : {MODES}")
    print(f"  Queries: {len(TEST_QUERIES)}")
    print(f"  Output : {output_dir}/")
    print("="*70)

    # ── Load KnowledgeBase once (shared across all models) ────────────────
    print("\n[1/3] Loading Knowledge Base...")
    kb = KnowledgeBase()

    all_results = {}   # { model_name: benchmark_output }

    for model_name in model_names:

        print(f"\n{'='*70}")
        print(f"  MODEL: {model_name.upper()}")
        print(f"{'='*70}")

        # ── Load LLM ─────────────────────────────────────────────────────
        print(f"\n[Loading {model_name}...]")
        llm      = load_llm(model_name)
        pipeline = YARAPipeline(llm=llm, kb=kb)

        model_results  = []
        summary_data   = {mode: [] for mode in MODES}

        for q_idx, (query, reference) in enumerate(
            zip(TEST_QUERIES, REFERENCES), 1
        ):
            print(f"\n  Query {q_idx}/{len(TEST_QUERIES)}: {query[:60]}...")
            query_row = {"query": query, "reference": reference}

            for mode in MODES:
                print(f"    [{mode:8}] ", end="", flush=True)

                # ── Run pipeline ─────────────────────────────────────────
                try:
                    result = pipeline.run(query, mode=mode)
                    rule   = result["yara_rule"]

                    # ── Compute metrics ───────────────────────────────────
                    metrics = evaluate_result(
                        query     = query,
                        generated = rule,
                        reference = reference,
                        retrieved = result.get("sources", [])
                    )

                    query_row[mode] = {
                        "yara_rule"     : rule,
                        "metrics"       : metrics,
                        "sources"       : [s["id"] for s in result.get("sources", [])],
                        "valid"         : result.get("valid", validate(rule)["is_valid"]),
                        "iterations"    : result.get("iterations", 1),
                        "retriever_used": result.get("retriever_used", "dense"),
                    }
                    summary_data[mode].append(metrics)

                    # ── Print inline result ───────────────────────────────
                    v_icon = "✅" if metrics["yara_valid"] else "❌"
                    print(
                        f"{v_icon} "
                        f"BLEU={metrics['bleu']:.3f} "
                        f"Syntax={metrics['syntax_score']:.2f} "
                        f"Hallu={metrics['hallucination_score']:.2f}"
                    )

                    if verbose:
                        print_rule_box(query, rule, mode)

                except Exception as e:
                    print(f"❌ ERROR: {e}")
                    query_row[mode] = {"error": str(e), "yara_rule": "", "metrics": {}}
                    summary_data[mode].append({})

            model_results.append(query_row)

        # ── Average metrics per mode ──────────────────────────────────────
        summary = {
            mode: average_metrics([r for r in summary_data[mode] if r])
            for mode in MODES
        }

        all_results[model_name] = {
            "per_query": model_results,
            "summary"  : summary,
        }

        # ── Print model summary table ─────────────────────────────────────
        print(f"\n{'─'*70}")
        print(f"  SUMMARY — {model_name.upper()}")
        print(f"{'─'*70}")
        df = pd.DataFrame(summary).T
        print(df.to_string())

    return {
        "timestamp" : timestamp,
        "models"    : model_names,
        "queries"   : TEST_QUERIES,
        "results"   : all_results,
    }


# ── Save results ─────────────────────────────────────────────────────────────

def save_results(bench: dict, output_dir: str = "results"):
    """Save benchmark results to JSON, CSV and TXT."""
    ts = bench["timestamp"]
    os.makedirs(output_dir, exist_ok=True)

    # ── 1. Full JSON ──────────────────────────────────────────────────────
    json_path = os.path.join(output_dir, f"benchmark_{ts}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(bench, f, indent=2, ensure_ascii=False)
    print(f"\n  Saved: {json_path}")

    # ── 2. CSV summary table ──────────────────────────────────────────────
    rows = []
    for model_name, data in bench["results"].items():
        for mode, metrics in data["summary"].items():
            row = {"model": model_name, "mode": mode}
            row.update(metrics)
            rows.append(row)

    csv_path = os.path.join(output_dir, f"benchmark_summary_{ts}.csv")
    df = pd.DataFrame(rows)
    df.to_csv(csv_path, index=False)
    print(f"  Saved: {csv_path}")

    # ── 3. Human-readable report ──────────────────────────────────────────
    txt_path = os.path.join(output_dir, f"benchmark_report_{ts}.txt")
    with open(txt_path, "w", encoding="utf-8") as f:

        f.write("="*70 + "\n")
        f.write("YARA RAG SYSTEM — BENCHMARK REPORT\n")
        f.write(f"Generated : {ts}\n")
        f.write(f"Models    : {bench['models']}\n")
        f.write(f"Queries   : {len(bench['queries'])}\n")
        f.write("="*70 + "\n\n")

        for model_name, data in bench["results"].items():
            f.write(f"\n{'─'*70}\n")
            f.write(f"MODEL: {model_name.upper()}\n")
            f.write(f"{'─'*70}\n\n")

            # Summary table
            f.write("SUMMARY METRICS (averaged over all queries):\n\n")
            df_model = pd.DataFrame(data["summary"]).T
            f.write(df_model.to_string() + "\n\n")

            # Per-query details
            f.write("PER-QUERY RESULTS:\n\n")
            for i, row in enumerate(data["per_query"], 1):
                f.write(f"Query {i}: {row['query']}\n")
                for mode in MODES:
                    if mode in row and "metrics" in row[mode]:
                        m = row[mode]["metrics"]
                        rule_preview = row[mode]["yara_rule"][:80].replace("\n", " ")
                        f.write(f"  [{mode:8}] {format_metrics(m)}\n")
                        f.write(f"            Rule: {rule_preview}...\n")
                f.write("\n")

        # Best model/mode analysis
        f.write("\n" + "="*70 + "\n")
        f.write("ANALYSIS\n")
        f.write("="*70 + "\n\n")

        best_syntax  = ("", "", 0.0)
        best_bleu    = ("", "", 0.0)
        most_halluc  = ("", "", 0.0)

        for model_name, data in bench["results"].items():
            for mode, metrics in data["summary"].items():
                if metrics.get("syntax_score", 0) > best_syntax[2]:
                    best_syntax = (model_name, mode, metrics["syntax_score"])
                if metrics.get("bleu", 0) > best_bleu[2]:
                    best_bleu = (model_name, mode, metrics["bleu"])
                if metrics.get("hallucination_score", 0) > most_halluc[2]:
                    most_halluc = (model_name, mode, metrics["hallucination_score"])

        f.write(f"Best syntax score  : {best_syntax[0]} / {best_syntax[1]} = {best_syntax[2]:.4f}\n")
        f.write(f"Best BLEU score    : {best_bleu[0]} / {best_bleu[1]} = {best_bleu[2]:.4f}\n")
        f.write(f"Most hallucinations: {most_halluc[0]} / {most_halluc[1]} = {most_halluc[2]:.4f}\n")

    print(f"  Saved: {txt_path}")
    return json_path, csv_path, txt_path


# ── CLI ──────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="YARA RAG System — Full Benchmark"
    )
    parser.add_argument(
        "--models", nargs="+",
        choices=["qwen", "mistral", "flan", "all"],
        default=["qwen"],
        help="Models to benchmark (default: qwen)"
    )
    parser.add_argument(
        "--output", type=str, default="results",
        help="Output directory for results (default: results/)"
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress per-rule output"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    model_list = list(MODELS.keys()) if "all" in args.models else args.models
    verbose    = not args.quiet

    # ── Run benchmark ─────────────────────────────────────────────────────
    bench = run_benchmark(
        model_names = model_list,
        output_dir  = args.output,
        verbose     = verbose
    )

    # ── Save results ──────────────────────────────────────────────────────
    print("\n[3/3] Saving results...")
    json_f, csv_f, txt_f = save_results(bench, args.output)

    # ── Final summary ─────────────────────────────────────────────────────
    print("\n" + "="*70)
    print("  BENCHMARK COMPLETE")
    print("="*70)
    print(f"  Models tested : {model_list}")
    print(f"  Queries       : {len(TEST_QUERIES)}")
    print(f"  Modes         : {MODES}")
    print(f"  Results saved to: {args.output}/")
    print("\n  Files generated:")
    print(f"    📊 {csv_f}   ← open in Excel")
    print(f"    📋 {txt_f}   ← human report")
    print(f"    🗂️  {json_f}  ← full raw data")

    # ── Print final comparison table ──────────────────────────────────────
    print("\n  FINAL COMPARISON TABLE:")
    rows = []
    for model_name, data in bench["results"].items():
        for mode, metrics in data["summary"].items():
            rows.append({
                "Model"   : model_name,
                "Mode"    : mode,
                "Syntax"  : metrics.get("syntax_score", 0),
                "BLEU"    : metrics.get("bleu", 0),
                "ROUGE-L" : metrics.get("rouge_l", 0),
                "SemSim"  : metrics.get("semantic_similarity", 0),
                "Valid"   : metrics.get("yara_valid", 0),
                "Hallu"   : metrics.get("hallucination_score", 0),
                "P@k"     : metrics.get("precision_at_k", 0),
                "MRR"     : metrics.get("mrr", 0),
            })
    df_final = pd.DataFrame(rows).set_index(["Model", "Mode"])
    print(df_final.to_string())
    print()
