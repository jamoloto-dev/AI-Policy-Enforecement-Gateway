import React, { useState } from 'react';
import {
  FlaskConical,
  Play,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Filter,
  Check,
  RefreshCw,
  TrendingUp,
  ShieldCheck,
  Info
} from 'lucide-react';
import { PolicyRule, TestCase, TestExecutionResult } from '../types/gateway';
import { executeGatewayInspection } from '../lib/detectorEngine';

interface SecurityTestLabProps {
  policies: PolicyRule[];
  sampleCases: TestCase[];
}

export const SecurityTestLab: React.FC<SecurityTestLabProps> = ({
  policies,
  sampleCases
}) => {
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [results, setResults] = useState<TestExecutionResult[] | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'PASSED' | 'FAILED'>('ALL');

  const runAllTests = async () => {
    setIsRunning(true);
    setResults(null);

    // Simulate batch execution with a short delay for animation
    setTimeout(() => {
      const execResults: TestExecutionResult[] = sampleCases.map((tc) => {
        const inspection = executeGatewayInspection(tc.input, policies);
        const actualDecision = inspection.finalDecision;
        const actualRules = inspection.triggeredRules;

        const decisionMatch = actualDecision === tc.expected_decision;
        let rulesMatch = true;
        if (tc.expected_rules.length > 0) {
          rulesMatch = tc.expected_rules.some((r) => actualRules.includes(r));
        } else {
          rulesMatch = actualRules.length === 0;
        }

        const passed = decisionMatch && rulesMatch;

        return {
          caseId: tc.id,
          name: tc.name,
          category: tc.category,
          inputSnippet: tc.input.length > 80 ? tc.input.slice(0, 80) + '...' : tc.input,
          expectedDecision: tc.expected_decision,
          actualDecision,
          expectedRules: tc.expected_rules,
          actualRules,
          riskScore: inspection.riskScore,
          passed,
          executionTimeMs: inspection.executionTimeMs,
          explanation: inspection.decisionReason
        };
      });

      setResults(execResults);
      setIsRunning(false);
    }, 400);
  };

  // Compute metrics if results exist
  const total = results ? results.length : sampleCases.length;
  const passedCount = results ? results.filter((r) => r.passed).length : 0;
  const failedCount = results ? results.filter((r) => !r.passed).length : 0;
  const accuracy = results ? ((passedCount / total) * 100).toFixed(1) : '0.0';

  // False positives: Benign marked as not ALLOW
  const falsePositives = results
    ? results.filter((r) => r.category === 'BENIGN' && r.actualDecision !== 'ALLOW').length
    : 0;
  // False negatives: Malicious marked as ALLOW
  const falseNegatives = results
    ? results.filter((r) => r.category !== 'BENIGN' && r.actualDecision === 'ALLOW').length
    : 0;

  // Filtered results
  const filteredResults = (results || []).filter((r) => {
    if (categoryFilter !== 'ALL' && r.category !== categoryFilter) return false;
    if (statusFilter === 'PASSED' && !r.passed) return false;
    if (statusFilter === 'FAILED' && r.passed) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <FlaskConical className="w-5 h-5 text-cyan-400" />
            <span>Security Test Lab & Benchmark Suite</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Repeatable evaluation of {sampleCases.length} positive and negative test cases to measure detection accuracy, false positives, and policy precedence.
          </p>
        </div>

        <button
          onClick={runAllTests}
          disabled={isRunning}
          className="px-5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-600 text-slate-950 font-bold text-xs flex items-center gap-2 transition-all shadow-md shadow-cyan-950/60 shrink-0 cursor-pointer"
        >
          {isRunning ? (
            <>
              <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
              <span>Executing Benchmark...</span>
            </>
          ) : (
            <>
              <Play className="w-4 h-4 fill-current" />
              <span>{results ? 'Re-run Test Suite' : 'Run 24 Benchmark Tests'}</span>
            </>
          )}
        </button>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="text-[11px] font-mono uppercase text-slate-400">Total Benchmark Cases</div>
          <div className="text-2xl font-bold font-mono text-slate-100 mt-1">{total}</div>
          <div className="text-[10px] text-slate-500 mt-0.5">Prompt Injection + PII + Benign</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="text-[11px] font-mono uppercase text-slate-400">Accuracy Score</div>
          <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">
            {results ? `${accuracy}%` : '--'}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">
            {results ? `${passedCount} of ${total} passed` : 'Pending execution'}
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="text-[11px] font-mono uppercase text-slate-400">False Positives (FP)</div>
          <div
            className={`text-2xl font-bold font-mono mt-1 ${
              falsePositives > 0 ? 'text-amber-400' : 'text-emerald-400'
            }`}
          >
            {results ? falsePositives : '--'}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Benign inputs falsely flagged</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="text-[11px] font-mono uppercase text-slate-400">False Negatives (FN)</div>
          <div
            className={`text-2xl font-bold font-mono mt-1 ${
              falseNegatives > 0 ? 'text-rose-400' : 'text-emerald-400'
            }`}
          >
            {results ? falseNegatives : '--'}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Threats slipping through to model</div>
        </div>
      </div>

      {/* Test Case Table & Filters */}
      <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
        {/* Filters */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-slate-400">Category:</span>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Categories</option>
              <option value="BENIGN">Benign (Negative Control)</option>
              <option value="PROMPT_INJECTION">Prompt Injection</option>
              <option value="SENSITIVE_DATA">Sensitive Data (PII)</option>
              <option value="CREDENTIAL_EXPOSURE">Credential Exposure</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-slate-400">Status:</span>
            <div className="inline-flex rounded-lg bg-slate-950 p-0.5 border border-slate-800">
              {(['ALL', 'PASSED', 'FAILED'] as const).map((st) => (
                <button
                  key={st}
                  onClick={() => setStatusFilter(st)}
                  className={`px-2.5 py-1 rounded text-[11px] transition-all ${
                    statusFilter === st
                      ? 'bg-slate-800 text-cyan-300 font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Results Table */}
        {!results ? (
          <div className="p-8 text-center text-xs text-slate-500 font-mono">
            Click <strong>Run 24 Benchmark Tests</strong> above to execute the automated verification suite.
          </div>
        ) : filteredResults.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500 font-mono">
            No test cases match the active filter criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="pb-2.5">ID</th>
                  <th className="pb-2.5">STATUS</th>
                  <th className="pb-2.5">NAME</th>
                  <th className="pb-2.5">CATEGORY</th>
                  <th className="pb-2.5">EXPECTED</th>
                  <th className="pb-2.5">ACTUAL</th>
                  <th className="pb-2.5">RISK</th>
                  <th className="pb-2.5">LATENCY</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredResults.map((r) => {
                  const decisionColors: Record<string, string> = {
                    ALLOW: 'text-emerald-400',
                    WARN: 'text-amber-400',
                    REDACT: 'text-cyan-400',
                    BLOCK: 'text-rose-400'
                  };

                  return (
                    <tr key={r.caseId} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-2.5 text-cyan-300 font-bold">{r.caseId}</td>
                      <td className="py-2.5">
                        {r.passed ? (
                          <span className="inline-flex items-center gap-1 text-emerald-400 font-bold bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-900/60 text-[10px]">
                            <CheckCircle2 className="w-3 h-3" /> PASS
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-rose-400 font-bold bg-rose-950/40 px-2 py-0.5 rounded border border-rose-900/60 text-[10px]">
                            <XCircle className="w-3 h-3" /> FAIL
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 text-slate-200">
                        <div className="font-semibold">{r.name}</div>
                        <div className="text-[10px] text-slate-500 truncate max-w-sm" title={r.inputSnippet}>
                          {r.inputSnippet}
                        </div>
                      </td>
                      <td className="py-2.5 text-slate-400 text-[11px]">{r.category}</td>
                      <td className="py-2.5 font-bold text-slate-300">{r.expectedDecision}</td>
                      <td className={`py-2.5 font-bold ${decisionColors[r.actualDecision]}`}>
                        {r.actualDecision}
                      </td>
                      <td className="py-2.5 text-slate-300">{r.riskScore}/100</td>
                      <td className="py-2.5 text-slate-500 whitespace-nowrap">{r.executionTimeMs} ms</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
