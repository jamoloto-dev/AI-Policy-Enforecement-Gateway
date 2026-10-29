export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type EnforcementAction = 'ALLOW' | 'WARN' | 'REDACT' | 'BLOCK';
export type ThreatCategory =
  | 'PROMPT_INJECTION'
  | 'SENSITIVE_DATA'
  | 'CREDENTIAL_EXPOSURE'
  | 'GUARDRAIL_BYPASS'
  | 'BENIGN';

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  category: ThreatCategory;
  severity: SeverityLevel;
  action: EnforcementAction;
  enabled: boolean;
  patterns: string[];
}

export interface DetectorFinding {
  ruleId: string;
  ruleName: string;
  category: ThreatCategory;
  severity: SeverityLevel;
  action: EnforcementAction;
  explanation: string;
  matchedSnippet: string;
  startPos: number;
  endPos: number;
  metadata?: Record<string, unknown>;
}

export interface InspectionResult {
  requestId: string;
  timestamp: string;
  rawInput: string;
  normalizedInput: string;
  finalDecision: EnforcementAction;
  riskScore: number;
  riskLevel: SeverityLevel;
  findings: DetectorFinding[];
  triggeredRules: string[];
  redactedOutput: string | null;
  forwardedToModel: boolean;
  executionTimeMs: number;
  decisionReason: string;
}

export interface AuditEvent {
  eventId: string;
  timestamp: string;
  requestId: string;
  decision: EnforcementAction;
  riskScore: number;
  riskLevel: SeverityLevel;
  triggeredRules: string;
  categories: string;
  inputLength: number;
  maskedSnippet: string;
  redactedPreview: string | null;
  executionTimeMs: number;
}

export interface TestCase {
  id: string;
  name: string;
  category: ThreatCategory;
  input: string;
  expected_decision: EnforcementAction;
  expected_rules: string[];
  description: string;
}

export interface TestExecutionResult {
  caseId: string;
  name: string;
  category: ThreatCategory;
  inputSnippet: string;
  expectedDecision: EnforcementAction;
  actualDecision: EnforcementAction;
  expectedRules: string[];
  actualRules: string[];
  riskScore: number;
  passed: boolean;
  executionTimeMs: number;
  explanation: string;
}
