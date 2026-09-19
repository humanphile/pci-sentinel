import React, { useEffect, useState } from 'react';
import { useLocalAI } from '../hooks/useLocalAI';

interface Props {
  requirementText: string;
}

export const AIControlAssistant: React.FC<Props> = ({ requirementText }) => {
  const { isReady, statusText, error, initRuntime, queryAI } = useLocalAI();
  const [analysis, setAnalysis] = useState<string>('');
  const [analyzing, setAnalyzing] = useState(false);

  useEffect(() => {
    initRuntime();
  }, [initRuntime]);

  const handleAnalyzeRequirement = async () => {
    try {
      setAnalyzing(true);
      const prompt = `Evaluate compliance evidence mapping for this PCI DSS requirement:\n\n${requirementText}`;
      const result = await queryAI(prompt, 'You are an auditor assistant for PCI DSS v4.0 compliance.');
      setAnalysis(result);
    } catch (err: any) {
      setAnalysis(`Analysis failed: ${err.message}`);
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="p-4 border rounded bg-slate-900 text-slate-100 space-y-3">
      <div className="flex items-center justify-between text-xs text-slate-400">
        <span>Runtime Status: {statusText}</span>
        {isReady && <span className="text-emerald-400 font-mono">● Port 8080</span>}
      </div>

      {error && <div className="text-red-400 text-xs">Error: {error}</div>}

      <button
        onClick={handleAnalyzeRequirement}
        disabled={!isReady || analyzing}
        className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded text-sm font-medium"
      >
        {analyzing ? 'Reasoning locally...' : 'Analyze Requirement via Local LLM'}
      </button>

      {analysis && (
        <div className="mt-3 p-3 bg-slate-800 rounded text-sm whitespace-pre-wrap font-sans">
          {analysis}
        </div>
      )}
    </div>
  );
};
