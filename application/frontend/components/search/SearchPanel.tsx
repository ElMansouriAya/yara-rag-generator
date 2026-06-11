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
            <div className="space-y-4">
              {results.map((result, idx) => (
                <div key={idx} className="border border-gray-200 rounded-lg p-4 hover:bg-gray-50">
                  <div className="mb-3 flex items-start justify-between">
                    <div className="flex-1">
                      <p className="text-xs text-gray-500 uppercase font-semibold mb-1">Source</p>
                      <p className="font-medium text-gray-900">
                        {result.source || 'Unknown'}
                        {result.doc_type && ` (${result.doc_type.toUpperCase()})`}
                      </p>
                    </div>
                    <div className="text-right">
                      <p className="text-xs text-gray-500 uppercase font-semibold">Score</p>
                      <div className="flex items-center gap-2 justify-end mt-1">
                        <div className="w-20 h-2 bg-gray-200 rounded-full overflow-hidden">
                          <div 
                            className="h-full bg-blue-500 rounded-full" 
                            style={{ width: `${(result.similarity || 0) * 100}%` }}
                          />
                        </div>
                        <span className="font-semibold text-gray-900 text-sm">
                          {((result.similarity || 0) * 100).toFixed(1)}%
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="mb-3 p-3 bg-gray-50 rounded text-sm text-gray-700 border-l-4 border-blue-400 max-h-20 overflow-hidden">
                    {result.content}
                  </div>

                  <div className="flex items-center justify-between text-xs">
                    <div className="text-gray-500">
                      <span className="font-semibold">Chunk ID:</span> {result.chunk_id || 'N/A'}
                    </div>
                    <span className={`px-2 py-1 rounded-full font-semibold ${
                      result.doc_type === 'pdf' 
                        ? 'bg-orange-100 text-orange-800' 
                        : 'bg-blue-100 text-blue-800'
                    }`}>
                      {result.doc_type === 'pdf' ? 'Uploaded PDF' : 'Original Dataset'}
                    </span>
                  </div>
                </div>
              ))}
            </div>
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
