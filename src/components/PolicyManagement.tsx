import React, { useState } from 'react';
import {
  Sliders,
  Save,
  RotateCcw,
  AlertTriangle,
  CheckCircle2,
  Code,
  Layers,
  Shield,
  FileCheck,
  Check
} from 'lucide-react';
import { PolicyRule, EnforcementAction, SeverityLevel } from '../types/gateway';
import { DEFAULT_POLICIES } from '../lib/defaultPolicies';

interface PolicyManagementProps {
  policies: PolicyRule[];
  onSavePolicies: (updated: PolicyRule[]) => void;
}

export const PolicyManagement: React.FC<PolicyManagementProps> = ({
  policies,
  onSavePolicies
}) => {
  const [localPolicies, setLocalPolicies] = useState<PolicyRule[]>(policies);
  const [mode, setMode] = useState<'visual' | 'json'>('visual');
  const [jsonText, setJsonText] = useState<string>(() => JSON.stringify(policies, null, 2));
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [saveSuccess, setSaveSuccess] = useState<boolean>(false);

  // Toggle single rule enabled state
  const handleToggleRule = (id: string) => {
    const updated = localPolicies.map((p) => (p.id === id ? { ...p, enabled: !p.enabled } : p));
    setLocalPolicies(updated);
    setJsonText(JSON.stringify(updated, null, 2));
  };

  // Change action
  const handleActionChange = (id: string, action: EnforcementAction) => {
    const updated = localPolicies.map((p) => (p.id === id ? { ...p, action } : p));
    setLocalPolicies(updated);
    setJsonText(JSON.stringify(updated, null, 2));
  };

  // Change severity
  const handleSeverityChange = (id: string, severity: SeverityLevel) => {
    const updated = localPolicies.map((p) => (p.id === id ? { ...p, severity } : p));
    setLocalPolicies(updated);
    setJsonText(JSON.stringify(updated, null, 2));
  };

  // Save changes
  const handleSave = () => {
    try {
      if (mode === 'json') {
        const parsed = JSON.parse(jsonText);
        if (!Array.isArray(parsed)) {
          throw new Error('Policy configuration must be a JSON array of rules.');
        }
        // Basic schema check
        for (const item of parsed) {
          if (!item.id || !item.name || !item.action || !item.category) {
            throw new Error(`Rule missing required fields (id, name, action, or category): ${JSON.stringify(item)}`);
          }
        }
        setLocalPolicies(parsed);
        onSavePolicies(parsed);
      } else {
        onSavePolicies(localPolicies);
      }

      setJsonError(null);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 2500);
    } catch (err: unknown) {
      setJsonError((err as Error).message || 'Invalid JSON syntax or schema.');
    }
  };

  // Reset to defaults
  const handleResetDefaults = () => {
    setLocalPolicies(DEFAULT_POLICIES);
    setJsonText(JSON.stringify(DEFAULT_POLICIES, null, 2));
    onSavePolicies(DEFAULT_POLICIES);
    setJsonError(null);
    setSaveSuccess(true);
    setTimeout(() => setSaveSuccess(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Sliders className="w-5 h-5 text-cyan-400" />
            <span>Policy Engine Configuration</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Configure security rules, enforcement actions (ALLOW, WARN, REDACT, BLOCK), and pattern thresholds.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={handleResetDefaults}
            className="px-3 py-1.5 rounded-lg border border-slate-800 hover:border-slate-700 bg-slate-900 text-xs text-slate-400 hover:text-slate-200 font-mono flex items-center gap-1.5 transition-all"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset Defaults</span>
          </button>

          <button
            onClick={handleSave}
            className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-all shadow-md shadow-cyan-950/60"
          >
            {saveSuccess ? (
              <>
                <Check className="w-3.5 h-3.5 text-slate-950" />
                <span>Saved!</span>
              </>
            ) : (
              <>
                <Save className="w-3.5 h-3.5" />
                <span>Save Policies</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Mode Tabs */}
      <div className="flex items-center justify-between text-xs font-mono">
        <div className="inline-flex rounded-lg bg-slate-950 p-1 border border-slate-800">
          <button
            onClick={() => setMode('visual')}
            className={`px-3 py-1 rounded text-xs flex items-center gap-1.5 transition-all ${
              mode === 'visual'
                ? 'bg-slate-800 text-cyan-300 font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Visual Rule Cards</span>
          </button>
          <button
            onClick={() => setMode('json')}
            className={`px-3 py-1 rounded text-xs flex items-center gap-1.5 transition-all ${
              mode === 'json'
                ? 'bg-slate-800 text-cyan-300 font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Code className="w-3.5 h-3.5" />
            <span>JSON Editor</span>
          </button>
        </div>

        <div className="text-[11px] text-slate-500">
          Strict Precedence: <span className="text-rose-400 font-bold">BLOCK</span> &gt; <span className="text-cyan-400">REDACT</span> &gt; <span className="text-amber-400">WARN</span> &gt; ALLOW
        </div>
      </div>

      {jsonError && (
        <div className="p-3.5 rounded-xl bg-rose-950/40 border border-rose-800/80 text-rose-300 text-xs font-mono flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div>
            <div className="font-bold">Configuration Error:</div>
            <div>{jsonError}</div>
          </div>
        </div>
      )}

      {saveSuccess && (
        <div className="p-3.5 rounded-xl bg-emerald-950/40 border border-emerald-800/80 text-emerald-300 text-xs font-mono flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>Policies successfully updated, validated, and applied across active gateway pipelines.</span>
        </div>
      )}

      {/* Visual Rule Cards Mode */}
      {mode === 'visual' ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {localPolicies.map((p) => {
            const isBlock = p.action === 'BLOCK';
            const isRedact = p.action === 'REDACT';
            const isWarn = p.action === 'WARN';

            return (
              <div
                key={p.id}
                className={`p-4 rounded-xl border transition-all ${
                  !p.enabled
                    ? 'bg-slate-950/40 border-slate-900 opacity-60'
                    : isBlock
                    ? 'bg-slate-900/80 border-rose-900/40'
                    : isRedact
                    ? 'bg-slate-900/80 border-cyan-900/40'
                    : isWarn
                    ? 'bg-slate-900/80 border-amber-900/40'
                    : 'bg-slate-900/80 border-slate-800'
                }`}
              >
                {/* Header */}
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-cyan-300 text-xs">{p.id}</span>
                    <span className="text-slate-600">•</span>
                    <span className="text-xs font-bold text-slate-200">{p.name}</span>
                  </div>

                  <label className="flex items-center gap-2 cursor-pointer select-none">
                    <span className="text-[10px] font-mono text-slate-400">
                      {p.enabled ? 'ENABLED' : 'DISABLED'}
                    </span>
                    <input
                      type="checkbox"
                      checked={p.enabled}
                      onChange={() => handleToggleRule(p.id)}
                      className="rounded bg-slate-950 border-slate-700 text-cyan-500 focus:ring-0 focus:ring-offset-0 cursor-pointer"
                    />
                  </label>
                </div>

                <p className="text-[11px] text-slate-400 mt-2 leading-relaxed">
                  {p.description}
                </p>

                {/* Controls */}
                <div className="grid grid-cols-2 gap-2 mt-4 pt-3 border-t border-slate-800/80 text-xs font-mono">
                  <div>
                    <label className="text-[10px] text-slate-500 block mb-1">Enforcement Action:</label>
                    <select
                      value={p.action}
                      onChange={(e) => handleActionChange(p.id, e.target.value as EnforcementAction)}
                      className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
                    >
                      <option value="ALLOW">ALLOW</option>
                      <option value="WARN">WARN</option>
                      <option value="REDACT">REDACT</option>
                      <option value="BLOCK">BLOCK</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-[10px] text-slate-500 block mb-1">Severity Weight:</label>
                    <select
                      value={p.severity}
                      onChange={(e) => handleSeverityChange(p.id, e.target.value as SeverityLevel)}
                      className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
                    >
                      <option value="LOW">LOW (+5 pts)</option>
                      <option value="MEDIUM">MEDIUM (+15 pts)</option>
                      <option value="HIGH">HIGH (+25 pts)</option>
                      <option value="CRITICAL">CRITICAL (+40 pts)</option>
                    </select>
                  </div>
                </div>

                {/* Patterns preview */}
                <div className="mt-3 text-[10px] font-mono text-slate-500 truncate">
                  Patterns ({p.patterns.length}): <code className="text-slate-400">{p.patterns[0]}</code>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        /* JSON Editor Mode */
        <div className="space-y-3">
          <textarea
            value={jsonText}
            onChange={(e) => setJsonText(e.target.value)}
            rows={18}
            className="w-full bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-xs text-slate-200 focus:outline-none focus:border-cyan-500/80 leading-relaxed resize-y"
          />
          <div className="text-[11px] text-slate-400 font-mono flex items-center gap-2">
            <FileCheck className="w-4 h-4 text-cyan-400" />
            <span>Direct JSON configuration mirrors <code>config/policies.json</code> in repository.</span>
          </div>
        </div>
      )}
    </div>
  );
};
