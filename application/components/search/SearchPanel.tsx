'use client'

import { useState } from 'react'
import { searchKB } from '@/lib/api-client'
import { SourceDoc } from '@/types/index'
import Toast from '@/components/shared/Toast'
import SourceCards from '@/components/generate/SourceCards'

export default function SearchPanel() {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<SourceDoc[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [searched, setSearched] = useState(false)

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!query.trim()) {
      setError('Please enter a search query')
      return
    }

    setIsLoading(true)
    setError(null)
    setSearched(true)

    try {
      const res = await searchKB(query, 10)
      setResults(res.results || [])
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Search failed'
      setError(message)
      setResults([])
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="bg-white border border-border rounded-lg p-6 shadow-sm">
        <h2 className="text-2xl font-bold text-foreground mb-4">Search Knowledge Base</h2>
        <form onSubmit={handleSearch} className="flex gap-2">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search for malware, rules, or descriptions…"
            className="flex-1 px-4 py-2 border border-border rounded-md bg-white text-foreground placeholder-muted focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
          />
          <button
            type="submit"
            disabled={isLoading}
            className="px-6 py-2 bg-primary text-white rounded-md font-medium hover:bg-primary-dark disabled:opacity-50 transition-colors"
          >
            {isLoading ? 'Searching…' : 'Search'}
          </button>
        </form>
      </div>

      {searched && (
        <div className="bg-white border border-border rounded-lg p-6 shadow-sm">
          <h3 className="text-lg font-bold text-foreground mb-4">
            Results {results.length > 0 && `(${results.length} found)`}
          </h3>
          {results.length > 0 ? (
            <SourceCards sources={results} />
          ) : (
            <div className="text-center py-8 text-muted">
              No results found
            </div>
          )}
        </div>
      )}

      {error && <Toast type="error" message={error} onClose={() => setError(null)} />}
    </div>
  )
}
