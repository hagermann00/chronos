import { Stage0FailClosedError } from './pathSecurity.ts';
import type { SanitizedStage0Report } from './types.ts';

const SECRET_AND_LEAK_PATTERNS: Array<{ code: string; regex: RegExp }> = [
  { code: 'GOOGLE_API_KEY', regex: /AIza[0-9A-Za-z_-]{20,}/ },
  { code: 'OPENAI_OR_ANTHROPIC_KEY', regex: /\bsk-[A-Za-z0-9_-]{16,}/ },
  { code: 'GITHUB_TOKEN', regex: /\bgh[pousr]_[A-Za-z0-9]{20,}/ },
  { code: 'SLACK_TOKEN', regex: /\bxox[baprs]-[A-Za-z0-9-]{12,}/ },
  { code: 'BEARER_HEADER', regex: /Bearer\s+[A-Za-z0-9._~+/=-]{16,}/i },
  { code: 'PRIVATE_KEY_PEM', regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/ },
  { code: 'EMAIL_ADDRESS_LEAK', regex: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/ },
  { code: 'POSIX_HOME_PATH_LEAK', regex: /\/(?:Users|home)\/[A-Za-z0-9._-]+\// },
  { code: 'WINDOWS_USER_PATH_LEAK', regex: /[A-Za-z]:\\Users\\[A-Za-z0-9._ -]+\\/i },
];

const FORBIDDEN_JSON_KEYS = new Set([
  'content',
  'text',
  'message',
  'messages',
  'prompt',
  'completion',
  'title',
  'conversation_title',
  'raw_path',
  'absolutePath',
  'targetValue',
  'apiKey',
  'token',
  'secret',
  'transcript',
  'row_values',
]);

const ALLOWED_TOP_LEVEL_KEYS = new Set([
  'schemaVersion',
  'stage',
  'evidenceOrigin',
  'generatedAtIso',
  'hostProfile',
  'securityAudit',
  'reuseInventory',
  'formatInventory',
]);

export interface SanitizationAuditResult {
  valid: boolean;
  violations: string[];
}

function inspectNodeRecursively(
  node: unknown,
  keyPath: string,
  violations: string[]
): void {
  if (node === null || node === undefined) return;

  if (typeof node === 'string') {
    if (node.length > 280) {
      violations.push(`STRING_TOO_LONG_POTENTIAL_CONTENT_LEAK at ${keyPath} (len=${node.length})`);
    }
    for (const pat of SECRET_AND_LEAK_PATTERNS) {
      if (pat.regex.test(node)) {
        violations.push(`PROHIBITED_PATTERN:${pat.code} at ${keyPath}`);
      }
    }
    return;
  }

  if (Array.isArray(node)) {
    node.forEach((item, idx) => inspectNodeRecursively(item, `${keyPath}[${idx}]`, violations));
    return;
  }

  if (typeof node === 'object') {
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      if (FORBIDDEN_JSON_KEYS.has(k)) {
        violations.push(`FORBIDDEN_KEY:${k} at ${keyPath}.${k}`);
      }
      inspectNodeRecursively(v, `${keyPath}.${k}`, violations);
    }
  }
}

/**
 * Validates that a Stage 0 report contains strictly structural metadata:
 * zero secrets, zero conversation bodies/titles, zero emails, zero user home paths,
 * and zero raw 86 target path strings.
 */
export function auditSanitizedStage0Report(candidate: unknown): SanitizationAuditResult {
  const violations: string[] = [];

  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    return { valid: false, violations: ['REPORT_NOT_OBJECT'] };
  }

  const obj = candidate as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    if (!ALLOWED_TOP_LEVEL_KEYS.has(key)) {
      violations.push(`UNEXPECTED_TOP_LEVEL_KEY:${key}`);
    }
  }

  if (obj.schemaVersion !== '1.0.0') {
    violations.push('INVALID_SCHEMA_VERSION');
  }
  if (obj.stage !== 'STAGE_0_READ_ONLY_DISCOVERY') {
    violations.push('INVALID_STAGE_TAG');
  }

  // Ensure every format inventory item stays strictly UNVERIFIED
  if (Array.isArray(obj.formatInventory)) {
    for (const item of obj.formatInventory as Array<Record<string, unknown>>) {
      if (item.verificationStatus !== 'UNVERIFIED') {
        violations.push(
          `PREMATURE_VERIFIED_ADAPTER_CLAIM:${String(item.ecosystem)}=${String(item.verificationStatus)}`
        );
      }
    }
  } else {
    violations.push('MISSING_FORMAT_INVENTORY_ARRAY');
  }

  // Ensure root aliases use opaque ROOT_* identifiers only
  const hostProfile = obj.hostProfile as Record<string, unknown> | undefined;
  if (hostProfile && Array.isArray(hostProfile.rootFilesystems)) {
    for (const rf of hostProfile.rootFilesystems as Array<Record<string, unknown>>) {
      if (typeof rf.rootAlias !== 'string' || !/^ROOT_[A-Z0-9_]{1,24}$/.test(rf.rootAlias)) {
        violations.push(`NON_OPAQUE_ROOT_ALIAS:${String(rf.rootAlias)}`);
      }
    }
  }

  // Ensure pruned86ByRuleId uses opaque rule IDs only, never path slashes
  const secAudit = obj.securityAudit as Record<string, unknown> | undefined;
  if (secAudit && secAudit.pruned86ByRuleId && typeof secAudit.pruned86ByRuleId === 'object') {
    for (const ruleKey of Object.keys(secAudit.pruned86ByRuleId as Record<string, unknown>)) {
      if (ruleKey.includes('/') || ruleKey.includes('\\') || ruleKey.includes(':')) {
        violations.push(`RAW_PATH_IN_86_RULE_KEY:${ruleKey}`);
      }
    }
  }

  inspectNodeRecursively(obj, '$', violations);

  return {
    valid: violations.length === 0,
    violations,
  };
}

export function assertSanitizedStage0Report(report: SanitizedStage0Report): string {
  const audit = auditSanitizedStage0Report(report);
  if (!audit.valid) {
    throw new Stage0FailClosedError(
      'FAIL_CLOSED_SANITIZATION_BREACH',
      audit.violations[0] ?? 'SANITIZATION_FAILED',
      `Refusing to serialize Stage 0 report due to sanitization violations: ${audit.violations.join('; ')}`
    );
  }
  return JSON.stringify(report, null, 2);
}
