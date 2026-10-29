import React, { useState } from 'react';
import {
  Search,
  ShieldAlert,
  ShieldCheck,
  ShieldBan,
  FileKey,
  AlertTriangle,
  Send,
  Trash2,
  Clock,
  Sparkles,
  ArrowRight,
  Server,
  CheckCircle2,
  XCircle,
  Copy,
  Check
} from 'lucide-react';
import { PolicyRule, InspectionResult, EnforcementAction, TestCase } from '../types/gateway';
import { executeGatewayInspection } from '../lib/detectorEngine';
import { saveAuditEvent } from '../lib/auditStorage';

interface LiveInspectionProps {
  policies: PolicyRule[];
  sampleCases: TestCase[];
  onInspectionComplete: () => void;
}

export const LiveInspection: React.FC<LiveInspectionProps> = ({
  policies,
  sampleCases,
  onInspectionComplete
}) => {
  const [inputText, setInputText] = useState<string>('');
  const [selectedCaseId, setSelectedCaseId] = useState<string>('');
  const [result, setResult] = useState<InspectionResult | null>(null);
  const [isCopied, setIsCopied] = useState<boolean>(false);

  const handleSelectCase = (caseId: string) => {
    setSelectedCaseId(caseId);
    if (!caseId) return;
    const found = sampleCases.find((c) => c.id === caseId);
    if (found) {
      setInputText(found.input);
      setResult(null);
    }
  };

  const handleClear = () => {
    setInputText('');
    setSelectedCaseId('');
    setResult(null);
  };

  const handleInspect = () => {
    if (!inputText.trim()) return;
    const inspection = executeGatewayInspection(inputText, policies);
    setResult(inspection);
    // Persist to audit storage
    saveAuditEvent(inspection);
    onInspectionComplete();
  };

  const copyRedactedText = () => {
    if (!result?.redactedOutput) return;
    navigator.clipboard.writeText(result.redactedOutput);
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="pb-2 border-b border-slate-800">
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <Search className="w-5 h-5 text-cyan-400" />
          <span>Live Prompt Inspection & Policy Enforcement</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Submit untrusted user text. The gateway normalizes input, evaluates active security rules, calculates risk scores, and applies allow, warn, redact, or block verdicts.
        </p>
      </div>

      {/* Input Section */}
      <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
        {/* Preset Selector */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <label className="text-xs font-semibold text-slate-300">
            Select Preset Attack / Benign Example:
          </label>
          <select
            value={selectedCaseId}
            onChange={(e) => handleSelectCase(e.target.value)}
            className="text-xs font-mono bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-cyan-300 focus:outline-none focus:border-cyan-500 max-w-md w-full"
          >
            <option value="">-- Choose from 24 Benchmark Test Cases --</option>
            {sampleCases.map((c) => (
              <option key={c.id} value={c.id}>
                [{c.id}] {c.name} ({c.expected_decision})
              </option>
            ))}
          </select>
        </div>

        {/* Text Area */}
        <div className="relative">
          <textarea
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            rows={5}
            placeholder="Type or paste an untrusted user prompt to inspect (e.g. 'Ignore all instructions...', or text with email/phone/SA ID)..."
            className="w-full bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/70 focus:ring-1 focus:ring-cyan-500/30 transition-all resize-y"
          />
          <div className="absolute bottom-3 right-3 text-[10px] font-mono text-slate-500 bg-slate-950/80 px-2 py-0.5 rounded border border-slate-800">
            {inputText.length} chars
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center justify-between pt-1">
          <button
            onClick={handleClear}
            disabled={!inputText && !result}
            className="px-3 py-1.5 rounded-lg border border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 text-xs font-mono flex items-center gap-1.5 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear Prompt</span>
          </button>

          <button
            onClick={handleInspect}
            disabled={!inputText.trim()}
            className="px-5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-600 text-slate-950 font-bold text-xs flex items-center gap-2 transition-all shadow-md shadow-cyan-950/60 disabled:shadow-none cursor-pointer disabled:cursor-not-allowed"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Inspect Input & Enforce</span>
          </button>
        </div>
      </div>

      {/* Decision & Results Panel */}
      {result && (
        <div className="space-y-6 animate-in fade-in duration-300">
          {/* Main Decision Banner */}
          <div
            className={`p-5 rounded-xl border relative overflow-hidden ${
              result.finalDecision === 'BLOCK'
                ? 'bg-rose-950/30 border-rose-600/50 text-rose-200 shadow-lg shadow-rose-950/40'
                : result.finalDecision === 'REDACT'
                ? 'bg-cyan-950/30 border-cyan-600/50 text-cyan-200 shadow-lg shadow-cyan-950/40'
                : result.finalDecision === 'WARN'
                ? 'bg-amber-950/30 border-amber-600/50 text-amber-200 shadow-lg shadow-amber-950/40'
                : 'bg-emerald-950/30 border-emerald-600/50 text-emerald-200 shadow-lg shadow-emerald-950/40'
            }`}
          >
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex items-start gap-3.5">
                <div className="mt-0.5">
                  {result.finalDecision === 'BLOCK' && <ShieldBan className="w-7 h-7 text-rose-400 animate-pulse" />}
                  {result.finalDecision === 'REDACT' && <FileKey className="w-7 h-7 text-cyan-400" />}
                  {result.finalDecision === 'WARN' && <AlertTriangle className="w-7 h-7 text-amber-400" />}
                  {result.finalDecision === 'ALLOW' && <ShieldCheck className="w-7 h-7 text-emerald-400" />}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono uppercase tracking-wider font-semibold opacity-75">
                      Enforcement Verdict
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase bg-black/40 border border-current">
                      {result.finalDecision}
                    </span>
                  </div>
                  <h3 className="text-base font-bold mt-0.5">{result.decisionReason}</h3>
                  <div className="text-xs opacity-80 mt-1 flex items-center gap-3 font-mono">
                    <span>Request ID: {result.requestId}</span>
                    <span>•</span>
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3" /> {result.executionTimeMs} ms
                    </span>
                  </div>
                </div>
              </div>

              {/* Downstream Model Handshake simulation indicator */}
              <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 text-xs font-mono shrink-0">
                <div className="text-[10px] text-slate-400 uppercase tracking-wider mb-1 flex items-center gap-1.5">
                  <Server className="w-3 h-3 text-cyan-400" />
                  <span>Downstream Model Ingress</span>
                </div>
                {result.forwardedToModel ? (
                  <div className="text-emerald-400 flex items-center gap-1.5 font-bold">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span>FORWARDED TO MODEL</span>
                  </div>
                ) : (
                  <div className="text-rose-400 flex items-center gap-1.5 font-bold">
                    <XCircle className="w-3.5 h-3.5 text-rose-400" />
                    <span>BLOCKED AT GATEWAY</span>
                  </div>
                )}
                <div className="text-[10px] text-slate-500 mt-1">
                  {result.forwardedToModel
                    ? 'Safe for upstream AI inference'
                    : 'Prompt dropped; zero tokens sent to AI'}
                </div>
              </div>
            </div>
          </div>

          {/* Risk Metrics & Gauge */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Risk Score */}
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
              <div className="text-xs font-mono uppercase text-slate-400">Calculated Risk Score</div>
              <div className="flex items-baseline gap-2 mt-1">
                <span
                  className={`text-3xl font-extrabold font-mono ${
                    result.riskScore >= 70
                      ? 'text-rose-400'
                      : result.riskScore >= 40
                      ? 'text-amber-400'
                      : 'text-emerald-400'
                  }`}
                >
                  {result.riskScore}
                </span>
                <span className="text-xs text-slate-500 font-mono">/ 100</span>
              </div>
              {/* Progress bar */}
              <div className="w-full bg-slate-950 rounded-full h-2 mt-3 overflow-hidden border border-slate-800">
                <div
                  className={`h-full transition-all duration-500 ${
                    result.riskScore >= 70
                      ? 'bg-rose-500'
                      : result.riskScore >= 40
                      ? 'bg-amber-500'
                      : 'bg-emerald-500'
                  }`}
                  style={{ width: `${result.riskScore}%` }}
                />
              </div>
            </div>

            {/* Risk Level */}
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
              <div className="text-xs font-mono uppercase text-slate-400">Threat Severity Rating</div>
              <div className="flex items-center gap-2 mt-2">
                <span
                  className={`px-3 py-1 rounded text-sm font-bold font-mono border ${
                    result.riskLevel === 'CRITICAL'
                      ? 'bg-rose-950/60 border-rose-700 text-rose-300'
                      : result.riskLevel === 'HIGH'
                      ? 'bg-amber-950/60 border-amber-700 text-amber-300'
                      : result.riskLevel === 'MEDIUM'
                      ? 'bg-yellow-950/40 border-yellow-700 text-yellow-300'
                      : 'bg-emerald-950/40 border-emerald-700 text-emerald-300'
                  }`}
                >
                  {result.riskLevel}
                </span>
              </div>
              <div className="text-[11px] text-slate-400 mt-2">
                Threshold: CRITICAL (70+), HIGH (40-69), MED (20-39), LOW (0-19)
              </div>
            </div>

            {/* Triggered Rules Summary */}
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
              <div className="text-xs font-mono uppercase text-slate-400">Triggered Rules Count</div>
              <div className="text-3xl font-extrabold font-mono text-cyan-300 mt-1">
                {result.findings.length}
              </div>
              <div className="text-[11px] text-slate-400 mt-2">
                {result.triggeredRules.length > 0 ? (
                  <span>Policy IDs: {result.triggeredRules.join(', ')}</span>
                ) : (
                  <span>Zero security policy violations</span>
                )}
              </div>
            </div>
          </div>

          {/* Triggered Rule Findings List */}
          {result.findings.length > 0 ? (
            <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
              <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider font-mono">
                Detector Findings ({result.findings.length})
              </h4>
              <div className="space-y-2.5">
                {result.findings.map((finding, idx) => (
                  <div
                    key={idx}
                    className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs font-mono"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-cyan-300">{finding.ruleId}</span>
                        <span className="text-slate-400">•</span>
                        <span className="text-slate-200 font-semibold">{finding.ruleName}</span>
                        <span className="text-slate-400">•</span>
                        <span className="text-slate-500">[{finding.category}]</span>
                      </div>
                      <div className="text-slate-400 text-[11px]">{finding.explanation}</div>
                      <div className="text-slate-300 text-[11px]">
                        Matched text: <code className="text-amber-300 bg-amber-950/30 px-1.5 py-0.5 rounded border border-amber-900/50">{finding.matchedSnippet}</code>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-900 border border-slate-700 text-slate-300">
                        {finding.severity}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                          finding.action === 'BLOCK'
                            ? 'bg-rose-950 text-rose-300 border-rose-800'
                            : finding.action === 'REDACT'
                            ? 'bg-cyan-950 text-cyan-300 border-cyan-800'
                            : 'bg-amber-950 text-amber-300 border-amber-800'
                        }`}
                      >
                        ACTION: {finding.action}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 text-xs font-mono text-emerald-400 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4" />
              <span>Clean Prompt: No adversarial triggers or sensitive entities were flagged.</span>
            </div>
          )}

          {/* Redacted Output / Safe Preview */}
          {result.finalDecision === 'REDACT' && result.redactedOutput && (
            <div className="p-5 rounded-xl bg-cyan-950/20 border border-cyan-800/40 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileKey className="w-4 h-4 text-cyan-400" />
                  <h4 className="text-xs font-bold text-cyan-200 uppercase tracking-wider font-mono">
                    Sanitized Output (Safe for Model Execution)
                  </h4>
                </div>
                <button
                  onClick={copyRedactedText}
                  className="px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-cyan-300 hover:bg-slate-800 flex items-center gap-1.5 transition-all"
                >
                  {isCopied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{isCopied ? 'Copied' : 'Copy Sanitized'}</span>
                </button>
              </div>

              <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 whitespace-pre-wrap leading-relaxed select-all">
                {result.redactedOutput}
              </div>

              <div className="text-[11px] text-cyan-400/80 font-mono">
                ✓ PII entities replaced with indexed deterministic tokens. Formatting and context preserved.
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
