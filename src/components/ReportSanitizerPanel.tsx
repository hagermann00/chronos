import { CheckCircle2, FileUp, ShieldAlert, Sparkles } from 'lucide-react';
import React, { useRef } from 'react';
import {
  SYNTHETIC_UNSANITIZED_LEAK_SAMPLE,
  SYNTHETIC_VALID_STAGE0_FIXTURE,
} from '../stage0/fixtures.ts';

interface ReportSanitizerPanelProps {
  rawReportInput: string;
  onChangeRawInput: (val: string) => void;
  auditResult: {
    ok: boolean;
    violations: string[];
    evidenceOrigin?: string;
  } | null;
  isAuditing: boolean;
  onValidateReportJson: (rawJsonOverride?: string) => void;
  onNavigateToAdr: () => void;
}

export const ReportSanitizerPanel: React.FC<ReportSanitizerPanelProps> = ({
  rawReportInput,
  onChangeRawInput,
  auditResult,
  isAuditing,
  onValidateReportJson,
  onNavigateToAdr,
}) => {
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    onChangeRawInput(text);
    onValidateReportJson(text);
  };

  const loadValidSyntheticFixture = () => {
    const formatted = JSON.stringify(SYNTHETIC_VALID_STAGE0_FIXTURE, null, 2);
    onChangeRawInput(formatted);
    onValidateReportJson(formatted);
  };

  const loadLeakViolationSample = () => {
    const formatted = JSON.stringify(SYNTHETIC_UNSANITIZED_LEAK_SAMPLE, null, 2);
    onChangeRawInput(formatted);
    onValidateReportJson(formatted);
  };

  return (
    <div className="space-y-8">
      <div className="flex flex-col gap-2 pb-5 border-b border-slate-200 dark:border-slate-800">
        <div className="text-xs text-slate-500 dark:text-slate-400">
          <span>03. Zero-Leak Output Sanitizer</span>
          <span className="mx-2" aria-hidden="true">·</span>
          <span>Blocks Secrets, Transcript Text, Titles, Emails &amp; Raw Paths</span>
          <span className="mx-2" aria-hidden="true">·</span>
          <span>Blocks Premature Adapter Claims</span>
        </div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100">
          Sanitized Stage 0 Evidence Intake &amp; Leak Guard
        </h1>
        <p className="text-sm text-slate-600 dark:text-slate-400 max-w-3xl leading-relaxed">
          Upload a sanitized <code className="font-mono text-xs">stage0-sanitized-report.json</code>{' '}
          produced on your Dell workstation, or test the Zero-Leak Sanitizer against structural and
          poisoned fixtures. Any payload containing credentials, user home paths, conversation
          titles/bodies, or non-<code className="font-mono text-xs">UNVERIFIED</code> adapter claims
          is rejected immediately.
        </p>
      </div>

      <section
        aria-labelledby="report-intake-heading"
        className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#111827] rounded-lg p-6 space-y-5"
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2
            id="report-intake-heading"
            className="text-base font-semibold text-slate-900 dark:text-slate-100"
          >
            Stage 0 Report JSON Payload
          </h2>

          <div className="flex flex-wrap items-center gap-2">
            <input
              ref={fileInputRef}
              type="file"
              accept=".json,application/json"
              onChange={handleFileUpload}
              className="hidden"
              id="stage0-file-upload"
            />
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border border-slate-300 dark:border-slate-700 rounded-md text-slate-800 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
            >
              <FileUp className="w-3.5 h-3.5" />
              Upload Workstation JSON
            </button>

            <button
              type="button"
              onClick={loadValidSyntheticFixture}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border border-slate-300 dark:border-slate-700 rounded-md text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
            >
              <Sparkles className="w-3.5 h-3.5" />
              Load Synthetic Structural Fixture
            </button>

            <button
              type="button"
              onClick={loadLeakViolationSample}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border border-rose-300 dark:border-rose-800/80 rounded-md text-rose-700 dark:text-rose-300 hover:bg-rose-50 dark:hover:bg-rose-950/30 transition-colors whitespace-nowrap shrink-0"
            >
              Test Unsanitized Leak Rejection
            </button>
          </div>
        </div>

        <div>
          <label htmlFor="raw-report-textarea" className="sr-only">
            Sanitized Stage 0 JSON Input
          </label>
          <textarea
            id="raw-report-textarea"
            rows={14}
            value={rawReportInput}
            onChange={(e) => onChangeRawInput(e.target.value)}
            placeholder='Paste sanitized Stage 0 JSON report here, or click "Load Synthetic Structural Fixture" to test schema validation...'
            className="w-full p-4 text-xs font-mono bg-slate-50 dark:bg-[#0B1120] border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-500 leading-relaxed"
          />
        </div>

        <div className="flex items-center justify-between gap-4">
          <div className="text-xs text-slate-500 dark:text-slate-400">
            Zero data leaves this session; validation executes deterministically against structural
            allowlists.
          </div>
          <button
            type="button"
            onClick={() => onValidateReportJson()}
            disabled={isAuditing || !rawReportInput.trim()}
            className="px-4 py-2 text-xs font-medium bg-sky-600 hover:bg-sky-500 text-white rounded-md transition-colors disabled:opacity-50 whitespace-nowrap shrink-0"
          >
            {isAuditing ? 'Auditing Payload...' : 'Run Zero-Leak Sanitizer Audit'}
          </button>
        </div>

        {auditResult && !auditResult.ok && (
          <div
            role="alert"
            className="p-5 rounded-md border border-rose-300 dark:border-rose-800 bg-rose-50 dark:bg-rose-950/30 space-y-3"
          >
            <div className="flex items-center gap-2 text-xs font-semibold text-rose-800 dark:text-rose-300 font-mono">
              <ShieldAlert className="w-4 h-4 shrink-0" />
              FAIL_CLOSED_SANITIZATION_BREACH — {auditResult.violations.length} Violation(s) Blocked
            </div>
            <ul className="space-y-1.5 text-xs font-mono text-rose-700 dark:text-rose-300 list-disc pl-5">
              {auditResult.violations.map((v, i) => (
                <li key={i}>{v}</li>
              ))}
            </ul>
          </div>
        )}

        {auditResult && auditResult.ok && (
          <div className="p-5 rounded-md border border-emerald-300 dark:border-emerald-800/80 bg-emerald-50/70 dark:bg-emerald-950/25 flex flex-wrap items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="inline-flex items-center gap-2 text-xs font-semibold font-mono text-emerald-800 dark:text-emerald-300">
                <CheckCircle2 className="w-4 h-4" />
                ZERO_LEAK_AUDIT_PASSED · Origin: {auditResult.evidenceOrigin}
              </div>
              <p className="text-xs text-emerald-700 dark:text-emerald-400">
                Verified structural-only report: zero secrets, zero conversation text/titles, opaque
                root aliases, and all adapters preserved as UNVERIFIED.
              </p>
            </div>

            <button
              type="button"
              onClick={onNavigateToAdr}
              className="px-3.5 py-2 text-xs font-medium bg-emerald-700 hover:bg-emerald-600 text-white rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              Open 4-Factor Priority &amp; Reuse ADR
            </button>
          </div>
        )}
      </section>
    </div>
  );
};
