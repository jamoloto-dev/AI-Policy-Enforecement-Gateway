import React from 'react';
import {
  FileText,
  Shield,
  AlertTriangle,
  CheckCircle,
  Binary,
  Layers,
  Lock,
  Cpu,
  BookOpen
} from 'lucide-react';

export const SecurityInformation: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="pb-2 border-b border-slate-800">
        <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <BookOpen className="w-5 h-5 text-cyan-400" />
          <span>Security Architecture & Detection Model</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Technical specifications, deterministic boundaries, threat categorizations, and defense-in-depth considerations.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Section 1: Pre-Inference Gateway Philosophy */}
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
          <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm">
            <Shield className="w-4 h-4" />
            <span>Zero-Trust Pre-Inference Gateway</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Standard AI application architectures pass raw user input directly to foundation model APIs. In contrast, the <strong>AI Policy Enforcement Gateway</strong> functions as an inline inspection proxy:
          </p>
          <ul className="text-xs text-slate-400 space-y-1.5 list-disc list-inside">
            <li><strong>Input Sanitization:</strong> Normalizes text, resolves Unicode homoglyphs (NFKC), and strips null bytes.</li>
            <li><strong>Sub-Millisecond Heuristics:</strong> Executes deterministic regular expressions and algorithmic validators before model tokens are consumed.</li>
            <li><strong>Guaranteed Enforcement:</strong> If an input violates a blocking policy, transmission to the model is aborted completely.</li>
          </ul>
        </div>

        {/* Section 2: Rule Precedence Logic */}
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
          <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm">
            <Layers className="w-4 h-4" />
            <span>Strict Rule Precedence Hierarchy</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            When a single prompt triggers multiple detector rules, the gateway applies deterministic precedence to prevent security bypasses:
          </p>
          <div className="space-y-2 text-xs font-mono">
            <div className="p-2 rounded bg-rose-950/30 border border-rose-800/60 text-rose-300 flex items-center justify-between">
              <span>1. BLOCK</span>
              <span className="text-[11px] opacity-80">Absolute rejection; overrides all other rules</span>
            </div>
            <div className="p-2 rounded bg-cyan-950/30 border border-cyan-800/60 text-cyan-300 flex items-center justify-between">
              <span>2. REDACT</span>
              <span className="text-[11px] opacity-80">Replaces sensitive PII; proceeds to inference</span>
            </div>
            <div className="p-2 rounded bg-amber-950/30 border border-amber-800/60 text-amber-300 flex items-center justify-between">
              <span>3. WARN</span>
              <span className="text-[11px] opacity-80">Flags suspicious patterns; logs audit event</span>
            </div>
            <div className="p-2 rounded bg-emerald-950/30 border border-emerald-800/60 text-emerald-300 flex items-center justify-between">
              <span>4. ALLOW</span>
              <span className="text-[11px] opacity-80">Clean input; passes unmodified</span>
            </div>
          </div>
        </div>

        {/* Section 3: South African ID & Luhn Checksum */}
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
          <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm">
            <Binary className="w-4 h-4" />
            <span>South African National ID Validation</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            The gateway does not simply match any 13-digit sequence. It implements the official South African National ID checksum:
          </p>
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 space-y-1">
            <div>Format: <strong className="text-cyan-300">YYMMDD GSSS C A Z</strong></div>
            <div className="text-slate-400">• YYMMDD: Birth date (validated for month 01-12, day 01-31)</div>
            <div className="text-slate-400">• GSSS: Gender (0-4999 Female, 5000-9999 Male)</div>
            <div className="text-slate-400">• C: Citizenship (0 = SA Citizen, 1 = Permanent Resident)</div>
            <div className="text-slate-400">• Z: Luhn checksum verification digit</div>
          </div>
          <p className="text-[11px] text-slate-400 italic">
            * Note: Mathematical validity confirms format conformity. It does not replace live identity verification against the National Population Register.
          </p>
        </div>

        {/* Section 4: Deterministic vs AI Model Boundaries */}
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
          <div className="flex items-center gap-2 text-amber-400 font-bold text-sm">
            <AlertTriangle className="w-4 h-4" />
            <span>Documented Limitations & Boundaries</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Transparently acknowledging the limits of deterministic rule-based security:
          </p>
          <ul className="text-xs text-slate-400 space-y-1.5 list-disc list-inside">
            <li><strong>Heuristic vs Semantic:</strong> Deterministic regex scans for signatures. It cannot detect intent in complex paraphrases or multilingual ciphers.</li>
            <li><strong>False Positives:</strong> Academic questions discussing prompt injection syntax will match patterns and trigger warnings.</li>
            <li><strong>Defense-in-Depth Layer 1:</strong> This gateway should be deployed alongside model system prompt hardening and output guardrails.</li>
          </ul>
        </div>
      </div>
    </div>
  );
};
