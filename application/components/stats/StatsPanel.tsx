'use client'

import { useEffect, useState } from 'react'
import { fetchStats } from '@/lib/api-client'
import { DatasetStats } from '@/types/index'
import { BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import Toast from '@/components/shared/Toast'

export default function StatsPanel() {
  const [stats, setStats] = useState<DatasetStats | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const loadStats = async () => {
      try {
        const data = await fetchStats()
        setStats(data)
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Failed to load stats'
        setError(message)
      } finally {
        setIsLoading(false)
      }
    }
    loadStats()
  }, [])

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin w-8 h-8 border-4 border-primary border-t-transparent rounded-full"></div>
      </div>
    )
  }

  if (!stats) {
    return <div className="text-center text-muted">Failed to load statistics</div>
  }

  const byTypeData = Object.entries(stats.by_type).map(([name, value]) => ({
    name,
    value,
  }))

  const byConfidenceData = Object.entries(stats.by_confidence).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value,
  }))

  const topFamiliesData = Object.entries(stats.top_families)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([name, value]) => ({
      name,
      value,
    }))

  const COLORS = ['#2563eb', '#3b82f6', '#60a5fa', '#93c5fd']

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white border border-border rounded-lg p-6 shadow-sm">
          <p className="text-sm text-muted mb-1">Total Rules</p>
          <p className="text-3xl font-bold text-primary">{stats.total}</p>
        </div>
        <div className="bg-white border border-border rounded-lg p-6 shadow-sm">
          <p className="text-sm text-muted mb-1">Synthetic</p>
          <p className="text-3xl font-bold text-secondary">{stats.synthetic}</p>
        </div>
        <div className="bg-white border border-border rounded-lg p-6 shadow-sm">
          <p className="text-sm text-muted mb-1">Original</p>
          <p className="text-3xl font-bold text-accent">{stats.original}</p>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Malware Type Distribution */}
        <div className="bg-white border border-border rounded-lg p-6 shadow-sm">
          <h3 className="text-lg font-bold text-foreground mb-4">Malware Type Distribution</h3>
          {byTypeData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={byTypeData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#cbd5e1" />
                <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 12 }} />
                <YAxis tick={{ fill: '#64748b', fontSize: 12 }} />
                <Tooltip contentStyle={{ backgroundColor: '#fff', border: '1px solid #cbd5e1' }} />
                <Bar dataKey="value" fill="#2563eb" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-muted">No data available</p>
          )}
        </div>

        {/* Confidence Distribution */}
        <div className="bg-white border border-border rounded-lg p-6 shadow-sm">
          <h3 className="text-lg font-bold text-foreground mb-4">Confidence Levels</h3>
          {byConfidenceData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={byConfidenceData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, value }) => `${name}: ${value}`}
                  outerRadius={80}
                  fill="#2563eb"
                  dataKey="value"
                >
                  {byConfidenceData.map((_, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-muted">No data available</p>
          )}
        </div>
      </div>

      {/* Top Malware Families */}
      <div className="bg-white border border-border rounded-lg p-6 shadow-sm">
        <h3 className="text-lg font-bold text-foreground mb-4">Top Malware Families</h3>
        <div className="space-y-2">
          {topFamiliesData.map((family, index) => (
            <div key={family.name} className="flex items-center gap-3">
              <div className="w-8 h-8 flex items-center justify-center bg-primary text-white rounded-full text-xs font-bold">
                {index + 1}
              </div>
              <div className="flex-1">
                <p className="font-medium text-foreground">{family.name}</p>
              </div>
              <div className="w-32 h-2 bg-muted-light rounded-full overflow-hidden">
                <div
                  className="h-full bg-primary transition-all"
                  style={{
                    width: `${Math.min((family.value / (topFamiliesData[0]?.value || 1)) * 100, 100)}%`,
                  }}
                ></div>
              </div>
              <span className="text-muted text-sm font-medium">{family.value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
