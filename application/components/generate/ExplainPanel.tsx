interface ExplainPanelProps {
  explanation: string
}

export default function ExplainPanel({ explanation }: ExplainPanelProps) {
  return (
    <div className="bg-white border border-border rounded-lg p-6 shadow-sm">
      <h3 className="text-lg font-bold text-foreground mb-4">YARA Rule Explanation</h3>
      <div className="prose prose-sm max-w-none">
        <p className="text-foreground whitespace-pre-wrap leading-relaxed">
          {explanation}
        </p>
      </div>
    </div>
  )
}
