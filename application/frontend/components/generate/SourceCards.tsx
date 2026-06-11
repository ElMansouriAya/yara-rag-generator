import { SourceDoc } from '@/types/index'

interface SourceCardsProps {
  sources: SourceDoc[]
}

export default function SourceCards({ sources }: SourceCardsProps) {
  if (sources.length === 0) {
    return (
      <div className="text-center py-8 text-muted">
        No sources retrieved for this query
      </div>
    )
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {sources.map((source) => (
        <div
          key={source.id}
          className="bg-white border border-border rounded-lg p-4 hover:shadow-md transition-shadow"
        >
          <div className="flex items-start justify-between gap-2 mb-2">
            <h4 className="font-bold text-foreground text-sm">{source.id}</h4>
            <span
              className={`px-2 py-1 rounded-full text-xs font-medium whitespace-nowrap ${
                source.confidence === 'high'
                  ? 'bg-emerald-100 text-emerald-800'
                  : 'bg-amber-100 text-amber-800'
              }`}
            >
              {source.confidence === 'high' ? '🔒 High' : '⚠️ Medium'}
            </span>
          </div>

          <p className="text-xs text-muted mb-1">
            {source.malware_type} • {source.malware_family}
          </p>

          <p className="text-sm text-foreground mb-3 line-clamp-2">
            {source.description}
          </p>

          <div className="flex items-center gap-2 text-xs">
            <span className="text-muted">Relevance:</span>
            <div className="flex-1 h-1.5 bg-muted-light rounded-full overflow-hidden">
              <div
                className="h-full bg-primary transition-all"
                style={{ width: `${Math.round(source.score * 100)}%` }}
              ></div>
            </div>
            <span className="text-muted font-medium">{source.score.toFixed(2)}</span>
          </div>
        </div>
      ))}
    </div>
  )
}
