'use client'

import { useState } from 'react'
import { explainRule } from '@/lib/api-client'
import { GenerateResult } from '@/types/index'
import Toast from '@/components/shared/Toast'

interface YaraOutputProps {
  result: GenerateResult
  onExplainSuccess: (explanation: string) => void
}

export default function YaraOutput({ result, onExplainSuccess }: YaraOutputProps) {
  const [isCopied, setIsCopied] = useState(false)
  const [isExplaining, setIsExplaining] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleCopy = () => {
    navigator.clipboard.writeText(result.yara_rule)
    setIsCopied(true)
    setTimeout(() => setIsCopied(false), 2000)
  }

  const handleDownload = () => {
    const blob = new Blob([result.yara_rule], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'rule.yar'
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleExplain = async () => {
    setIsExplaining(true)
    setError(null)
    try {
      const res = await explainRule(result.yara_rule)
      onExplainSuccess(res.explanation)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to explain'
      setError(message)
    } finally {
      setIsExplaining(false)
    }
  }

  const syntaxPercent = Math.round((result.syntax_score || 0) * 100)

  return (
    <div className="bg-white border border-border rounded-lg p-6 shadow-sm">
      <div className="space-y-4">
        <div>
          <h3 className="text-sm font-medium text-foreground mb-2">YARA Rule</h3>
          <pre className="yara-code">
            {result.yara_rule}
          </pre>
        </div>

        <div className="flex flex-wrap items-center gap-4 text-sm">
          <div className="flex items-center gap-2">
            <span className={`px-2 py-1 rounded-full text-xs font-medium ${
              result.valid
                ? 'bg-green-100 text-green-800'
                : 'bg-red-100 text-red-800'
            }`}>
              {result.valid ? '✅ Valid' : '❌ Invalid'}
            </span>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-foreground font-medium">Syntax:</span>
            <div className="w-32 h-2 bg-muted-light rounded-full overflow-hidden">
              <div
                className="h-full bg-primary transition-all"
                style={{ width: `${syntaxPercent}%` }}
              ></div>
            </div>
            <span className="text-muted">{syntaxPercent}%</span>
          </div>

          <div className="text-muted text-xs">
            Retriever: <span className="font-medium text-foreground">{result.retriever_used}</span> • 
            Iterations: <span className="font-medium text-foreground">{result.iterations}</span>
          </div>
        </div>

        <div className="flex gap-2 pt-4 border-t border-border">
          <button
            onClick={handleCopy}
            className="flex-1 px-3 py-2 bg-muted-light text-foreground rounded-md font-medium hover:bg-border transition-colors"
          >
            {isCopied ? '✓ Copied' : 'Copy'}
          </button>
          <button
            onClick={handleExplain}
            disabled={isExplaining}
            className="flex-1 px-3 py-2 bg-primary text-white rounded-md font-medium hover:bg-primary-dark disabled:opacity-50 transition-colors"
          >
            {isExplaining ? 'Explaining…' : 'Explain'}
          </button>
          <button
            onClick={handleDownload}
            className="flex-1 px-3 py-2 bg-primary-light text-white rounded-md font-medium hover:bg-primary transition-colors"
          >
            Download
          </button>
        </div>
      </div>

      {error && <Toast type="error" message={error} onClose={() => setError(null)} />}
    </div>
  )
}
