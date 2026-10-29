import React from 'react';
import { Shield, ShieldAlert, Cpu, Activity, Terminal } from 'lucide-react';
import { PolicyRule } from '../types/gateway';

interface NavbarProps {
  policies: PolicyRule[];
  onOpenCodeBrowser?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ policies, onOpenCodeBrowser }) => {
  const activeCount = policies.filter((p) => p.enabled).length;

  return (
    <header className="h-16 border-b border-slate-800 bg-slate-950/80 backdrop-blur-md sticky top-0 z-40 px-6 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <div className="relative flex items-center justify-center w-10 h-10 rounded-lg bg-cyan-950/60 border border-cyan-500/30 text-cyan-400 shadow-lg shadow-cyan-950/50">
          <Shield className="w-5 h-5 text-cyan-400 animate-pulse" />
          <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
          </span>
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-base font-bold tracking-tight text-slate-100 flex items-center gap-2">
              AI Policy Enforcement Gateway
            </h1>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-cyan-500/30 bg-cyan-950/40 text-cyan-300 font-semibold uppercase tracking-wider">
              Zero-Trust Layer
            </span>
          </div>
          <p className="text-xs text-slate-400 flex items-center gap-2">
            <span>Deterministic Prompt Inspection</span>
            <span className="text-slate-600">•</span>
            <span className="text-emerald-400 font-mono flex items-center gap-1">
              <Activity className="w-3 h-3 inline" /> Pre-Inference Active
            </span>
          </p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="hidden md:flex items-center gap-3 text-xs font-mono bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-lg text-slate-300">
          <Cpu className="w-3.5 h-3.5 text-cyan-400" />
          <span>Active Rules: <strong className="text-cyan-300">{activeCount}</strong>/{policies.length}</span>
          <span className="text-slate-700">|</span>
          <span className="text-slate-400">Precedence: <span className="text-rose-400 font-bold">BLOCK</span> &gt; <span className="text-cyan-400">REDACT</span> &gt; <span className="text-amber-400">WARN</span></span>
        </div>

        {onOpenCodeBrowser && (
          <button
            onClick={onOpenCodeBrowser}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 hover:border-cyan-500/50 text-xs font-mono text-cyan-300 transition-all shadow-sm"
          >
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span>Python Source & Tests</span>
          </button>
        )}
      </div>
    </header>
  );
};
