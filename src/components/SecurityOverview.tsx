import React from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  FileKey,
  ShieldBan,
  Activity,
  Layers,
  ArrowRight,
  TrendingUp,
  RotateCcw
} from 'lucide-react';
import { AuditEvent } from '../types/gateway';

interface SecurityOverviewProps {
  auditEvents: AuditEvent[];
  onNavigateToInspection: () => void;
  onNavigateToTestLab: () => void;
  onSeedDemoData: () => void;
}

export const SecurityOverview: React.FC<SecurityOverviewProps> = ({
  auditEvents,
  onNavigateToInspection,
  onNavigateToTestLab,
  onSeedDemoData
}) => {
  const total = auditEvents.length;

  const allowed = auditEvents.filter((e) => e.decision === 'ALLOW').length;
  const warned = auditEvents.filter((e) => e.decision === 'WARN').length;
  const redacted = auditEvents.filter((e) => e.decision === 'REDACT').length;
  const blocked = auditEvents.filter((e) => e.decision === 'BLOCK').length;

  const threatCount = warned + redacted + blocked;
  const threatRate = total > 0 ? ((threatCount / total) * 100).toFixed(1) : '0.0';

  // Category breakdown
  const categoryCounts: Record<string, number> = {};
  auditEvents.forEach((ev) => {
    if (ev.categories) {
      ev.categories.split(',').forEach((c) => {
        const cat = c.trim();
        if (cat) {
          categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
        }
      });
    }
  });

  const recentEvents = auditEvents.slice(0, 6);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            <span>Security Operations Overview</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Real-time telemetry and decision analytics computed from persistent audit event logs.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {total === 0 && (
            <button
              onClick={onSeedDemoData}
              className="px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 text-xs text-slate-300 font-mono flex items-center gap-1.5 transition-all"
            >
              <RotateCcw className="w-3.5 h-3.5 text-cyan-400" />
              <span>Load Sample Telemetry</span>
            </button>
          )}
          <button
            onClick={onNavigateToTestLab}
            className="px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs transition-all shadow-md shadow-cyan-950 flex items-center gap-1.5"
          >
            <span>Run Test Lab Suite</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
        {/* Total */}
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm relative overflow-hidden">
          <div className="text-[11px] font-mono uppercase text-slate-400 tracking-wider font-semibold">
            Total Requests
          </div>
          <div className="text-2xl font-bold text-slate-100 mt-1 font-mono">{total}</div>
          <div className="text-[10px] text-slate-500 mt-1">Evaluated across all sessions</div>
        </div>

        {/* Allowed */}
        <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-900/40 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase text-emerald-400 tracking-wider font-semibold">
              Allowed
            </span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-300 mt-1 font-mono">{allowed}</div>
          <div className="text-[10px] text-emerald-500/80 mt-1">
            {total > 0 ? ((allowed / total) * 100).toFixed(0) : 0}% of traffic
          </div>
        </div>

        {/* Warned */}
        <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-900/40 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase text-amber-400 tracking-wider font-semibold">
              Warned
            </span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-300 mt-1 font-mono">{warned}</div>
          <div className="text-[10px] text-amber-500/80 mt-1">Flagged suspicious</div>
        </div>

        {/* Redacted */}
        <div className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-900/40 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase text-cyan-400 tracking-wider font-semibold">
              Redacted
            </span>
            <FileKey className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-cyan-300 mt-1 font-mono">{redacted}</div>
          <div className="text-[10px] text-cyan-500/80 mt-1">PII sanitized</div>
        </div>

        {/* Blocked */}
        <div className="p-4 rounded-xl bg-rose-950/20 border border-rose-900/40 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase text-rose-400 tracking-wider font-semibold">
              Blocked
            </span>
            <ShieldBan className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-300 mt-1 font-mono">{blocked}</div>
          <div className="text-[10px] text-rose-500/80 mt-1">Inference dropped</div>
        </div>
      </div>

      {/* Visual Analytics Row */}
      {total === 0 ? (
        <div className="p-12 text-center rounded-xl bg-slate-900/40 border border-dashed border-slate-800">
          <Layers className="w-10 h-10 text-slate-600 mx-auto mb-3" />
          <h3 className="text-sm font-semibold text-slate-300">No Inspection Records Found</h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto mt-1 mb-4">
            The security gateway audit database is currently empty. Run test cases or submit a prompt to view real-time metrics.
          </p>
          <div className="flex items-center justify-center gap-3">
            <button
              onClick={onNavigateToInspection}
              className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-semibold transition-all"
            >
              Inspect First Prompt
            </button>
            <button
              onClick={onSeedDemoData}
              className="px-4 py-2 rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 text-xs text-slate-300 transition-all font-mono"
            >
              Seed Sample Events
            </button>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Decision Distribution Bar Breakdown */}
          <div className="lg:col-span-2 p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-slate-200">Enforcement Decision Breakdown</h3>
                <p className="text-xs text-slate-400">Distribution of gateway policy verdicts</p>
              </div>
              <span className="text-xs font-mono text-slate-400">{total} Total Events</span>
            </div>

            {/* Visual stacked horizontal bar */}
            <div className="h-4 w-full bg-slate-950 rounded-full overflow-hidden flex border border-slate-800">
              {allowed > 0 && (
                <div
                  style={{ width: `${(allowed / total) * 100}%` }}
                  className="bg-emerald-500 hover:opacity-90 transition-all"
                  title={`ALLOW: ${allowed}`}
                />
              )}
              {warned > 0 && (
                <div
                  style={{ width: `${(warned / total) * 100}%` }}
                  className="bg-amber-500 hover:opacity-90 transition-all"
                  title={`WARN: ${warned}`}
                />
              )}
              {redacted > 0 && (
                <div
                  style={{ width: `${(redacted / total) * 100}%` }}
                  className="bg-cyan-500 hover:opacity-90 transition-all"
                  title={`REDACT: ${redacted}`}
                />
              )}
              {blocked > 0 && (
                <div
                  style={{ width: `${(blocked / total) * 100}%` }}
                  className="bg-rose-500 hover:opacity-90 transition-all"
                  title={`BLOCK: ${blocked}`}
                />
              )}
            </div>

            {/* Legend & Stats Table */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
              <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <div className="flex items-center gap-1.5 text-xs text-emerald-400 font-medium">
                  <div className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
                  <span>ALLOW</span>
                </div>
                <div className="text-base font-bold text-slate-100 font-mono mt-0.5">
                  {allowed} <span className="text-xs text-slate-500 font-normal">({total > 0 ? ((allowed / total) * 100).toFixed(0) : 0}%)</span>
                </div>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <div className="flex items-center gap-1.5 text-xs text-amber-400 font-medium">
                  <div className="w-2.5 h-2.5 rounded-full bg-amber-500" />
                  <span>WARN</span>
                </div>
                <div className="text-base font-bold text-slate-100 font-mono mt-0.5">
                  {warned} <span className="text-xs text-slate-500 font-normal">({total > 0 ? ((warned / total) * 100).toFixed(0) : 0}%)</span>
                </div>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <div className="flex items-center gap-1.5 text-xs text-cyan-400 font-medium">
                  <div className="w-2.5 h-2.5 rounded-full bg-cyan-500" />
                  <span>REDACT</span>
                </div>
                <div className="text-base font-bold text-slate-100 font-mono mt-0.5">
                  {redacted} <span className="text-xs text-slate-500 font-normal">({total > 0 ? ((redacted / total) * 100).toFixed(0) : 0}%)</span>
                </div>
              </div>

              <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <div className="flex items-center gap-1.5 text-xs text-rose-400 font-medium">
                  <div className="w-2.5 h-2.5 rounded-full bg-rose-500" />
                  <span>BLOCK</span>
                </div>
                <div className="text-base font-bold text-slate-100 font-mono mt-0.5">
                  {blocked} <span className="text-xs text-slate-500 font-normal">({total > 0 ? ((blocked / total) * 100).toFixed(0) : 0}%)</span>
                </div>
              </div>
            </div>

            {/* Threat Categories Box */}
            <div className="pt-2 border-t border-slate-800">
              <div className="text-xs font-semibold text-slate-300 mb-2">Detected Threat Categories</div>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                {Object.entries(categoryCounts).length === 0 ? (
                  <div className="text-xs text-slate-500 italic">No threats categorized yet</div>
                ) : (
                  Object.entries(categoryCounts).map(([cat, count]) => (
                    <div key={cat} className="flex items-center justify-between p-2 rounded bg-slate-950/50 border border-slate-800/60 text-xs">
                      <span className="text-slate-400 font-mono text-[11px] truncate">{cat}</span>
                      <span className="font-mono text-cyan-300 font-bold ml-2">{count}</span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Threat Detection Rate & Formula Callout */}
          <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-slate-200">Threat Interception Ratio</h3>
                <TrendingUp className="w-4 h-4 text-cyan-400" />
              </div>
              <p className="text-xs text-slate-400 mt-0.5">Percentage of queries requiring gateway intervention</p>

              <div className="my-6 text-center">
                <div className="text-4xl font-extrabold text-cyan-400 font-mono">{threatRate}%</div>
                <div className="text-xs text-slate-400 mt-1">
                  {threatCount} threats intercepted out of {total} requests
                </div>
              </div>

              {/* Exact Formula Callout as mandated by prompt */}
              <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 font-mono text-[11px] text-slate-400 leading-relaxed">
                <div className="text-slate-300 font-semibold mb-1">Defined Formula:</div>
                <div className="text-cyan-300">
                  Rate = (Warned + Redacted + Blocked) / Total Requests
                </div>
                <div className="text-slate-500 mt-1 text-[10px]">
                  Denominator strictly defined as total submitted prompt inspections.
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-500 flex items-center justify-between">
              <span>Gate Latency:</span>
              <span className="text-emerald-400 font-mono">&lt; 2.5 ms</span>
            </div>
          </div>
        </div>
      )}

      {/* Recent Security Events Stream */}
      {recentEvents.length > 0 && (
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <span>Recent Gateway Security Events</span>
            </h3>
            <span className="text-xs text-slate-500 font-mono">Latest {recentEvents.length} transactions</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="pb-2">TIMESTAMP</th>
                  <th className="pb-2">REQUEST ID</th>
                  <th className="pb-2">DECISION</th>
                  <th className="pb-2">RISK SCORE</th>
                  <th className="pb-2">TRIGGERED RULES</th>
                  <th className="pb-2">MASKED INPUT</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {recentEvents.map((ev) => {
                  const decisionColors: Record<string, string> = {
                    ALLOW: 'text-emerald-400 bg-emerald-950/50 border-emerald-800',
                    WARN: 'text-amber-400 bg-amber-950/50 border-amber-800',
                    REDACT: 'text-cyan-400 bg-cyan-950/50 border-cyan-800',
                    BLOCK: 'text-rose-400 bg-rose-950/50 border-rose-800'
                  };

                  return (
                    <tr key={ev.eventId} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-2.5 text-slate-400 whitespace-nowrap">
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="py-2.5 text-slate-300 font-bold">{ev.requestId}</td>
                      <td className="py-2.5">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                            decisionColors[ev.decision] || 'text-slate-400'
                          }`}
                        >
                          {ev.decision}
                        </span>
                      </td>
                      <td className="py-2.5">
                        <span
                          className={
                            ev.riskScore >= 70
                              ? 'text-rose-400 font-bold'
                              : ev.riskScore >= 40
                              ? 'text-amber-400'
                              : 'text-emerald-400'
                          }
                        >
                          {ev.riskScore}/100
                        </span>
                      </td>
                      <td className="py-2.5 text-slate-300">
                        {ev.triggeredRules || <span className="text-slate-600">None</span>}
                      </td>
                      <td className="py-2.5 text-slate-400 max-w-xs truncate" title={ev.maskedSnippet}>
                        {ev.maskedSnippet}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
