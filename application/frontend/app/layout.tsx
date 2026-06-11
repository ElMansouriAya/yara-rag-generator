import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'GuardianYARA - YARA Rule Generator',
  description: 'AI-powered YARA rule generation using RAG pipeline',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="bg-white">
      <body className="bg-white text-foreground">
        {children}
      </body>
    </html>
  )
}
