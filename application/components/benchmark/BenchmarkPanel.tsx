'use client'

import { useState } from 'react'
import { runBenchmark } from '@/lib/api-client'
import { BenchmarkResult } from '@/types/index'
import Toast from '@/components/shared/Toast'

const DEFAULT_BENCHMARK_QUERIES = [
  'Ransomware encrypting files with AES and deleting shadow copies',
  'Keylogger intercepting keystrokes and exfiltrating via FTP',
  'Worm spreading through SMB network shares',
  'Backdoor using DNS tunneling for C2 communication',
  'Cryptominer using XMRig to mine Monero',
  'Trojan injecting code into browser to steal banking credentials',
  'Spyware taking screenshots and uploading via HTTP',
  'Dropper disguised as PDF downloading remote payload',
]

const DEFAULT_BENCHMARK_REFERENCES = [
  'rule AES_Ransomware { strings: $aes="AES" nocase $shadow="vssadmin delete shadows" nocase condition: $aes and $shadow }',
  'rule Keylogger_FTP { strings: $hook="SetWindowsHookEx" nocase $ftp="FtpPutFile" nocase condition: $hook and $ftp }',
  'rule SMB_Worm { strings: $smb="NetShareEnum" nocase $admin="ADMIN$" nocase condition: 2 of them }',
  'rule DNS_Backdoor { strings: $dns="DnsQuery" nocase $b64="base64" nocase condition: $dns and $b64 }',
  'rule XMRig_Miner { strings: $xmr="xmrig" nocase $stratum="stratum+tcp://" nocase condition: $xmr or $stratum }',
  'rule Banking_Trojan { strings: $crt="CreateRemoteThread" nocase $form="login.php" nocase condition: $crt and $form }',
  'rule Screenshot_Spy { strings: $blt="BitBlt" nocase $http="InternetOpenUrl" nocase condition: $blt and $http }',
  'rule Fake_PDF_Drop { strings: $pdf="%PDF" nocase $exec="WinExec" nocase condition: $pdf and $exec }',
]

const METRICS = [
  'bleu',
  'rouge_l',
  'semantic_similarity',
  'yara_valid',
  'syntax_score',
  'hallucination_score',
  'precision_at_k',
  'mrr',
]

const MODES = ['agentic', 'hybrid', 'classic', 'baseline']

export default function BenchmarkPanel() {
  const [isRunning, setIsRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<BenchmarkResult | null>(null)

  const handleRunBenchmark = async () => {
    setIsRunning(true)
    setError(null)

    try {
      const res = await runBenchmark(DEFAULT_BENCHMARK_QUERIES, DEFAULT_BENCHMARK_REFERENCES)
      setResult(res)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Benchmark failed'
      setError(message)
    } finally {
      setIsRunning(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="bg-white border border-border rounded-lg p-6 shadow-sm">
        <h2 className="text-2xl font-bold text-foreground mb-2">Run Benchmark</h2>
        <div className="bg-amber-50 border border-amber-200 rounded-md p-3 mb-4">
          <p className="text-sm text-amber-900">
            ⚠️ Benchmark runs all 4 modes across {DEFAULT_BENCHMARK_QUERIES.length} queries. This takes 5–15 minutes.
          </p>
        </div>
        <button
          onClick={handleRunBenchmark}
          disabled={isRunning}
          className="px-6 py-2 bg-primary text-white rounded-md font-medium hover:bg-primary-dark disabled:opacity-50 transition-colors flex items-center gap-2"
        >
          {isRunning ? (
            <>
              <span className="inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></span>
              Running benchmark…
            </>
          ) : (
            'Start Benchmark'
          )}
        </button>
      </div>

      {result && (
        <div className="bg-white border border-border rounded-lg p-6 shadow-sm">
          <h3 className="text-lg font-bold text-foreground mb-4">Summary Results</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left py-2 px-2 font-bold text-foreground">Mode</th>
                  {METRICS.map((metric) => (
                    <th key={metric} className="text-center py-2 px-2 font-bold text-foreground">
                      {metric.replace(/_/g, ' ')}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {MODES.map((mode) => {
                  const modeData = result.summary[mode as keyof typeof result.summary]
                  return (
                    <tr key={mode} className="border-b border-border hover:bg-muted-light">
                      <td className="py-3 px-2 font-medium text-foreground capitalize">{mode}</td>
                      {METRICS.map((metric) => {
                        const value = (modeData as any)[metric] as number
                        return (
                          <td key={metric} className="text-center py-3 px-2">
                            <span className="text-foreground font-medium">
                              {typeof value === 'number' ? value.toFixed(3) : 'N/A'}
                            </span>
                          </td>
                        )
                      })}
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {error && <Toast type="error" message={error} onClose={() => setError(null)} />}
    </div>
  )
}
