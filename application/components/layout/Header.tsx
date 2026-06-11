import { Dispatch, SetStateAction } from 'react'

type TabType = 'generate' | 'search' | 'benchmark' | 'stats'

interface HeaderProps {
  activeTab: TabType
  onTabChange: Dispatch<SetStateAction<TabType>>
  selectedModel: string
  onModelChange: Dispatch<SetStateAction<string>>
}

const MODELS = [
  { value: 'qwen', label: 'Qwen 0.5B (Fast)' },
  { value: 'flan', label: 'Flan-T5 (Lightweight)' },
  { value: 'mistral', label: 'Mistral 7B (Best)' },
]

const TABS = [
  { id: 'generate' as TabType, label: 'Generate' },
  { id: 'search' as TabType, label: 'Search' },
  { id: 'benchmark' as TabType, label: 'Benchmark' },
  { id: 'stats' as TabType, label: 'Stats' },
]

export default function Header({ activeTab, onTabChange, selectedModel, onModelChange }: HeaderProps) {
  return (
    <header className="bg-white border-b border-border shadow-sm">
      <div className="max-w-7xl mx-auto px-4 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-primary rounded-lg flex items-center justify-center">
              <span className="text-white font-bold text-lg">🛡</span>
            </div>
            <h1 className="text-2xl font-bold text-primary">GuardianYARA</h1>
          </div>

          <nav className="flex items-center gap-1">
            {TABS.map((tab) => (
              <button
                key={tab.id}
                onClick={() => onTabChange(tab.id)}
                className={`px-4 py-2 rounded-md font-medium transition-colors ${
                  activeTab === tab.id
                    ? 'bg-primary text-white'
                    : 'text-foreground hover:bg-muted-light'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </nav>

          <div className="flex items-center gap-2">
            <label htmlFor="model-select" className="text-sm font-medium text-foreground">
              Model:
            </label>
            <select
              id="model-select"
              value={selectedModel}
              onChange={(e) => onModelChange(e.target.value)}
              className="px-3 py-2 border border-border rounded-md bg-white text-foreground hover:border-primary focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
            >
              {MODELS.map((model) => (
                <option key={model.value} value={model.value}>
                  {model.label}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>
    </header>
  )
}
