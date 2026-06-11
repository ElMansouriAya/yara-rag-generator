'use client'

import React, { useState, useRef, useEffect } from 'react'
import { uploadPDF, getPDFStats, testPDFRetrieval } from '@/lib/api-client'

interface UploadResult {
  filename: string
  pages: number
  documents: number
  file_size: number
  upload_time: string
  processing_time?: number
  extraction_time?: number
  embedding_count?: number
  vector_indexed?: boolean
}

interface ProcessingStep {
  step: string
  completed: boolean
  timestamp?: string
}

export default function PDFUploader() {
  const [isUploading, setIsUploading] = useState(false)
  const [uploadResult, setUploadResult] = useState<UploadResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [processingSteps, setProcessingSteps] = useState<ProcessingStep[]>([])
  const [testQuery, setTestQuery] = useState('')
  const [testResults, setTestResults] = useState<any>(null)
  const [isTestingRetrieval, setIsTestingRetrieval] = useState(false)
  const [uploadHistory, setUploadHistory] = useState<any[]>([])
  const fileInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    loadUploadHistory()
  }, [])

  const loadUploadHistory = async () => {
    try {
      const stats = await getPDFStats()
      setUploadHistory(stats.uploads || [])
    } catch (err) {
      console.error('Failed to load upload history:', err)
    }
  }

  const handleFileSelect = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return

    if (!file.name.toLowerCase().endsWith('.pdf')) {
      setError('Please select a PDF file')
      return
    }

    await handleUpload(file)
  }

  const handleUpload = async (file: File) => {
    setIsUploading(true)
    setError(null)
    setUploadResult(null)
    setProcessingSteps([
      { step: 'PDF Uploaded', completed: true, timestamp: new Date().toISOString() },
      { step: 'Text Extracted', completed: false },
      { step: 'Chunks Created', completed: false },
      { step: 'Embeddings Generated', completed: false },
      { step: 'Added to Vector Database', completed: false },
      { step: 'Ready for Retrieval', completed: false },
    ])

    try {
      const result = await uploadPDF(file)
      
      // Simulate processing steps completion
      setProcessingSteps((prev) => {
        const updated = [...prev]
        updated[1] = { ...updated[1], completed: true, timestamp: new Date().toISOString() }
        updated[2] = { ...updated[2], completed: true, timestamp: new Date().toISOString() }
        updated[3] = { ...updated[3], completed: true, timestamp: new Date().toISOString() }
        updated[4] = { ...updated[4], completed: true, timestamp: new Date().toISOString() }
        updated[5] = { ...updated[5], completed: true, timestamp: new Date().toISOString() }
        return updated
      })
      
      setUploadResult(result)
      await loadUploadHistory()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed')
      setProcessingSteps([])
    } finally {
      setIsUploading(false)
      if (fileInputRef.current) {
        fileInputRef.current.value = ''
      }
    }
  }

  const handleTestRetrieval = async () => {
    if (!testQuery.trim() || !uploadResult) return

    setIsTestingRetrieval(true)
    try {
      const results = await testPDFRetrieval(testQuery, uploadResult.filename)
      setTestResults(results)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Test retrieval failed')
    } finally {
      setIsTestingRetrieval(false)
    }
  }

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()

    const files = e.dataTransfer.files
    if (files.length > 0) {
      const file = files[0]
      if (file.name.toLowerCase().endsWith('.pdf')) {
        handleUpload(file)
      } else {
        setError('Please drop a PDF file')
      }
    }
  }

  return (
    <div className="space-y-6">
      {/* Upload Area */}
      <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center hover:border-gray-400 transition-colors"
           onDragOver={handleDragOver}
           onDrop={handleDrop}>
        <input
          ref={fileInputRef}
          type="file"
          accept=".pdf"
          onChange={handleFileSelect}
          disabled={isUploading}
          className="hidden"
          id="pdf-input"
        />

        <label
          htmlFor="pdf-input"
          className="flex flex-col items-center cursor-pointer"
        >
          <svg
            className="w-12 h-12 mb-2 text-gray-400"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M9 19l3 3m0 0l3-3m-3 3V10"
            />
          </svg>

          <p className="text-gray-600">
            {isUploading ? 'Processing PDF...' : 'Drag and drop your PDF, or click to select'}
          </p>
        </label>
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-red-600">
          <p className="font-semibold mb-1">Error</p>
          <p className="text-sm">{error}</p>
        </div>
      )}

      {/* Processing Steps */}
      {processingSteps.length > 0 && (
        <div className="border border-gray-200 rounded-lg p-4 bg-gray-50">
          <h3 className="font-semibold text-gray-900 mb-4">Processing Status</h3>
          <div className="space-y-3">
            {processingSteps.map((step, index) => (
              <div key={index} className="flex items-center gap-3">
                <div className={`w-5 h-5 rounded-full flex items-center justify-center text-sm font-bold ${
                  step.completed 
                    ? 'bg-green-500 text-white' 
                    : 'bg-gray-300 text-gray-600'
                }`}>
                  {step.completed ? '✓' : index + 1}
                </div>
                <span className={step.completed ? 'text-gray-900' : 'text-gray-500'}>
                  {step.step}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Upload Result with Metrics */}
      {uploadResult && (
        <div className="border border-green-200 rounded-lg overflow-hidden bg-green-50">
          <div className="bg-green-100 border-b border-green-200 p-4">
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 rounded-full bg-green-500 text-white flex items-center justify-center text-sm font-bold">
                ✓
              </div>
              <h3 className="font-semibold text-green-900">PDF Successfully Indexed</h3>
            </div>
          </div>
          
          <div className="p-4 space-y-4">
            {/* Basic Info */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-xs text-gray-500 uppercase font-semibold">Filename</p>
                <p className="font-medium text-gray-900">{uploadResult.filename}</p>
              </div>
              <div>
                <p className="text-xs text-gray-500 uppercase font-semibold">Status</p>
                <p className="font-medium text-green-700">Indexed</p>
              </div>
              <div>
                <p className="text-xs text-gray-500 uppercase font-semibold">Pages</p>
                <p className="font-medium text-gray-900">{uploadResult.pages}</p>
              </div>
              <div>
                <p className="text-xs text-gray-500 uppercase font-semibold">Size</p>
                <p className="font-medium text-gray-900">{(uploadResult.file_size / 1024).toFixed(2)} KB</p>
              </div>
            </div>

            {/* Processing Metrics */}
            <div className="border-t border-gray-200 pt-4">
              <h4 className="font-semibold text-gray-900 mb-3 text-sm">Processing Metrics</h4>
              <div className="grid grid-cols-3 gap-3">
                <div className="bg-white rounded p-3">
                  <p className="text-xs text-gray-500 uppercase font-semibold">Chunks Created</p>
                  <p className="text-lg font-bold text-gray-900">{uploadResult.documents}</p>
                </div>
                <div className="bg-white rounded p-3">
                  <p className="text-xs text-gray-500 uppercase font-semibold">Embeddings</p>
                  <p className="text-lg font-bold text-gray-900">{uploadResult.embedding_count || uploadResult.documents}</p>
                </div>
                <div className="bg-white rounded p-3">
                  <p className="text-xs text-gray-500 uppercase font-semibold">Processing Time</p>
                  <p className="text-lg font-bold text-gray-900">{uploadResult.processing_time || 0}s</p>
                </div>
              </div>
            </div>

            {/* Test Retrieval */}
            <div className="border-t border-gray-200 pt-4">
              <h4 className="font-semibold text-gray-900 mb-3 text-sm">Test Retrieval</h4>
              <div className="flex gap-2 mb-3">
                <input
                  type="text"
                  placeholder="Search within this PDF..."
                  value={testQuery}
                  onChange={(e) => setTestQuery(e.target.value)}
                  className="flex-1 px-3 py-2 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
                <button
                  onClick={handleTestRetrieval}
                  disabled={!testQuery.trim() || isTestingRetrieval}
                  className="px-4 py-2 bg-blue-500 text-white rounded-md font-medium text-sm hover:bg-blue-600 disabled:bg-gray-400 transition-colors"
                >
                  {isTestingRetrieval ? 'Testing...' : 'Test'}
                </button>
              </div>
              
              {testResults && (
                <div className="bg-white border border-blue-200 rounded p-3">
                  <p className="text-xs text-gray-500 uppercase font-semibold mb-2">Retrieved Chunks</p>
                  <div className="space-y-2">
                    {testResults.results?.map((result: any, idx: number) => (
                      <div key={idx} className="text-sm border-l-4 border-blue-500 pl-3 py-2">
                        <p className="text-gray-600">{result.content.substring(0, 150)}...</p>
                        <p className="text-xs text-gray-500 mt-1">Score: {(result.score * 100).toFixed(1)}%</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Upload History Table */}
      {uploadHistory.length > 0 && (
        <div className="border border-gray-200 rounded-lg overflow-hidden">
          <div className="bg-gray-50 border-b border-gray-200 p-4">
            <h3 className="font-semibold text-gray-900">Upload History</h3>
          </div>
          
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-gray-200 bg-gray-50">
                <tr>
                  <th className="px-4 py-3 text-left font-semibold text-gray-900">Filename</th>
                  <th className="px-4 py-3 text-left font-semibold text-gray-900">Chunks</th>
                  <th className="px-4 py-3 text-left font-semibold text-gray-900">Pages</th>
                  <th className="px-4 py-3 text-left font-semibold text-gray-900">Status</th>
                  <th className="px-4 py-3 text-left font-semibold text-gray-900">Uploaded</th>
                </tr>
              </thead>
              <tbody>
                {uploadHistory.map((upload, idx) => (
                  <tr key={idx} className="border-b border-gray-200 hover:bg-gray-50">
                    <td className="px-4 py-3 font-medium text-gray-900">{upload.filename}</td>
                    <td className="px-4 py-3 text-gray-600">{upload.documents}</td>
                    <td className="px-4 py-3 text-gray-600">{upload.pages}</td>
                    <td className="px-4 py-3">
                      <span className="inline-block px-2 py-1 text-xs font-semibold bg-green-100 text-green-800 rounded">
                        {upload.status || 'Indexed'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-600 text-xs">
                      {new Date(upload.timestamp).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
