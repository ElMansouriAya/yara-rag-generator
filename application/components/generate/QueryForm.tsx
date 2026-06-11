'use client'

import { useState } from 'react'
import { generateRule } from '@/lib/api-client'
import { GenerateResult, RAGMode } from '@/types/index'
import Toast from '@/components/shared/Toast'

interface QueryFormProps {
  onSuccess: (result: GenerateResult) => void
  onLoadingChange: (isLoading: boolean) => void
}

const MODES: { value: RAGMode; label: string; tooltip: string }[] = [
  {
    value: 'agentic',
    label: 'Agentic',
    tooltip: 'Full agent loop — analyzes query, picks best retriever, validates and retries. Best quality.',
  },
  {
    value: 'hybrid',
    label: 'Hybrid',
    tooltip: 'Combines semantic (FAISS) and keyword (BM25) search. Good balance.',
  },
  {
    value: 'classic',
    label: 'Classic',
    tooltip: 'Semantic search only. Fast.',
  },
  {
    value: 'baseline',
    label: 'Baseline',
    tooltip: 'No retrieval — LLM only. Used for benchmarking.',
  },
]

export default function QueryForm({ onSuccess, onLoadingChange }: QueryFormProps) {
  const [query, setQuery] = useState('')
  const [mode, setMode] = useState<RAGMode>('agentic')
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!query.trim()) {
      setError('Please describe the malware behavior')
      return
    }

    setIsLoading(true)
    onLoadingChange(true)
    setError(null)
    setSuccess(null)

    try {
      const result = await generateRule(query, mode)
      onSuccess(result)
      setSuccess('YARA rule generated successfully')
      setQuery('')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to generate rule'
      setError(message)
    } finally {
      setIsLoading(false)
      onLoadingChange(false)
    }
  }

  return (
    <div className="bg-white border border-border rounded-lg p-6 shadow-sm">
      <h2 className="text-xl font-bold text-foreground mb-4">Generate YARA Rule</h2>
      
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="query" className="block text-sm font-medium text-foreground mb-2">
            Threat Description
          </label>
          <textarea
            id="query"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Describe the malware behavior — e.g. Ransomware encrypting files with AES and deleting shadow copies"
            rows={5}
            className="w-full px-3 py-2 border border-border rounded-md bg-white text-foreground placeholder-muted focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
          />
        </div>

        <div>
          <label htmlFor="mode" className="block text-sm font-medium text-foreground mb-2">
            RAG Mode
          </label>
          <div className="relative">
            <select
              id="mode"
              value={mode}
              onChange={(e) => setMode(e.target.value as RAGMode)}
              className="w-full px-3 py-2 border border-border rounded-md bg-white text-foreground hover:border-primary focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
            >
              {MODES.map((m) => (
                <option key={m.value} value={m.value}>
                  {m.label}
                </option>
              ))}
            </select>
            <div className="mt-1 text-xs text-muted">
              {MODES.find((m) => m.value === mode)?.tooltip}
            </div>
          </div>
        </div>

        <button
          type="submit"
          disabled={isLoading || !query.trim()}
          className="w-full px-4 py-2 bg-primary text-white rounded-md font-medium hover:bg-primary-dark disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
        >
          {isLoading ? (
            <>
              <span className="inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></span>
              Generating YARA rule…
            </>
          ) : (
            'Generate Rule'
          )}
        </button>
      </form>

      {error && <Toast type="error" message={error} onClose={() => setError(null)} />}
      {success && <Toast type="success" message={success} onClose={() => setSuccess(null)} />}
    </div>
  )
}
