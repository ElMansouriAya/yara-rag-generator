import { useEffect } from 'react'

interface ToastProps {
  type: 'success' | 'error'
  message: string
  onClose: () => void
  duration?: number
}

export default function Toast({ type, message, onClose, duration = 4000 }: ToastProps) {
  useEffect(() => {
    const timer = setTimeout(onClose, duration)
    return () => clearTimeout(timer)
  }, [onClose, duration])

  const bgColor = type === 'success' ? 'bg-green-100' : 'bg-red-100'
  const textColor = type === 'success' ? 'text-green-800' : 'text-red-800'
  const icon = type === 'success' ? '✓' : '✕'

  return (
    <div className={`${bgColor} ${textColor} px-4 py-3 rounded-md flex items-center gap-3 mt-4`}>
      <span className="font-bold">{icon}</span>
      <p className="flex-1">{message}</p>
      <button
        onClick={onClose}
        className="text-lg font-bold hover:opacity-70 transition-opacity"
      >
        ×
      </button>
    </div>
  )
}
