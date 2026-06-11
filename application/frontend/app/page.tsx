'use client'

import { useState } from 'react'
import Header from '@/components/layout/Header'
import QueryForm from '@/components/generate/QueryForm'
import YaraOutput from '@/components/generate/YaraOutput'
import SourceCards from '@/components/generate/SourceCards'
import ExplainPanel from '@/components/generate/ExplainPanel'
import SearchPanel from '@/components/search/SearchPanel'
import StatsPanel from '@/components/stats/StatsPanel'
import BenchmarkPanel from '@/components/benchmark/BenchmarkPanel'
import PDFUploader from '@/components/upload/PDFUploader'
import { GenerateResult } from '@/types/index'

type TabType = 'generate' | 'search' | 'benchmark' | 'stats' | 'upload'

export default function Home() {
  const [activeTab, setActiveTab] = useState<TabType>('generate')
  const [generatedResult, setGeneratedResult] = useState<GenerateResult | null>(null)
  const [explanation, setExplanation] = useState<string | null>(null)
  const [isGenerating, setIsGenerating] = useState(false)
  const [selectedModel, setSelectedModel] = useState('qwen')

  const handleGenerateSuccess = (result: GenerateResult) => {
    setGeneratedResult(result)
    setExplanation(null)
  }

  const handleExplainSuccess = (text: string) => {
    setExplanation(text)
  }

  return (
    <div className="min-h-screen bg-white">
      <Header 
        activeTab={activeTab} 
        onTabChange={setActiveTab}
        selectedModel={selectedModel}
        onModelChange={setSelectedModel}
      />
      
      <main className="max-w-7xl mx-auto px-4 py-8">
        {activeTab === 'generate' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-1">
              <QueryForm 
                onSuccess={handleGenerateSuccess}
                onLoadingChange={setIsGenerating}
              />
            </div>
            
            <div className="lg:col-span-2">
              {generatedResult ? (
                <div className="space-y-6">
                  <YaraOutput 
                    result={generatedResult}
                    onExplainSuccess={handleExplainSuccess}
                  />
                  {explanation && (
                    <ExplainPanel explanation={explanation} />
                  )}
                  {generatedResult.sources.length > 0 && (
                    <div>
                      <h2 className="text-2xl font-bold text-foreground mb-4">Retrieved Sources</h2>
                      <SourceCards sources={generatedResult.sources} />
                    </div>
                  )}
                </div>
              ) : (
                <div className="border-2 border-dashed border-border rounded-lg p-12 text-center">
                  <p className="text-muted text-lg">
                    Generate a YARA rule to see results here
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'search' && <SearchPanel />}
        {activeTab === 'benchmark' && <BenchmarkPanel />}
        {activeTab === 'stats' && <StatsPanel />}
        {activeTab === 'upload' && (
          <div className="max-w-2xl mx-auto">
            <h1 className="text-3xl font-bold text-foreground mb-2">Upload PDF Documents</h1>
            <p className="text-muted mb-8">Upload PDF files to augment your knowledge base with custom documents.</p>
            <PDFUploader />
          </div>
        )}
      </main>
    </div>
  )
}
