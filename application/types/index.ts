export type RAGMode = 'agentic' | 'hybrid' | 'classic' | 'baseline'
export type ModelName = 'qwen' | 'flan' | 'mistral'
export type Confidence = 'high' | 'medium'

export interface SourceDoc {
  id: string
  description: string
  malware_type: string
  malware_family: string
  score: number
  confidence: Confidence
  source_type: string
}

export interface GenerateResult {
  query: string
  mode: RAGMode
  yara_rule: string
  valid: boolean
  syntax_score: number
  sources: SourceDoc[]
  iterations: number
  retriever_used: string
  model: ModelName
}

export interface DatasetStats {
  total: number
  synthetic: number
  original: number
  by_type: Record<string, number>
  by_confidence: Record<string, number>
  top_families: Record<string, number>
}

export interface BenchmarkSummary {
  bleu: number
  rouge_l: number
  semantic_similarity: number
  yara_valid: number
  syntax_score: number
  hallucination_score: number
  precision_at_k: number
  mrr: number
}

export interface BenchmarkResult {
  summary: Record<RAGMode, BenchmarkSummary>
  per_query: Array<{
    query: string
    agentic: { yara_rule: string; metrics: BenchmarkSummary }
    hybrid: { yara_rule: string; metrics: BenchmarkSummary }
    classic: { yara_rule: string; metrics: BenchmarkSummary }
    baseline: { yara_rule: string; metrics: BenchmarkSummary }
  }>
  model: ModelName
}
