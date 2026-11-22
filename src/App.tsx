import { Moon, Sun } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { ConfigAndScriptsPanel } from './components/ConfigAndScriptsPanel.tsx';
import { PriorityAndReuseAdrPanel } from './components/PriorityAndReuseAdrPanel.tsx';
import { ReportSanitizerPanel } from './components/ReportSanitizerPanel.tsx';
import { SandboxVerificationPanel } from './components/SandboxVerificationPanel.tsx';
import {
  DEFAULT_EXTERNAL_86_MANIFEST,
  DEFAULT_NTFS_STAGE0_CONFIG,
  DEFAULT_POSIX_STAGE0_CONFIG,
  DEFAULT_WORKFLOW_WEIGHTS,
  SYNTHETIC_VALID_STAGE0_FIXTURE,
} from './stage0/fixtures.ts';
import type { SandboxVerificationSummary } from './stage0/sandboxVerifier.ts';
import type {
  AdapterPriorityScore,
  External86Manifest,
  SanitizedStage0Report,
  Stage0Config,
  VendorEcosystemId,
  WorkflowImportanceTier,
} from './stage0/types.ts';

type ActiveView = 'config' | 'sandbox' | 'sanitizer' | 'adr';

export default function App() {
  const [activeView, setActiveView] = useState<ActiveView>('config');
  const [isDark, setIsDark] = useState(true);

  const [config, setConfig] = useState<Stage0Config>(DEFAULT_NTFS_STAGE0_CONFIG);
  const [manifest, setManifest] = useState<External86Manifest>(DEFAULT_EXTERNAL_86_MANIFEST);
  const [validationState, setValidationState] = useState<{
    ok: boolean;
    failClosedCode?: string;
    detailCode?: string;
    message?: string;
    normalizedRootCount?: number;
    normalizedZoneBKey?: string;
    scripts?: { probeScriptMjs: string; canaryScriptMjs: string };
  } | null>(null);
  const [isValidatingConfig, setIsValidatingConfig] = useState(false);

  const [sandboxSummary, setSandboxSummary] = useState<SandboxVerificationSummary | null>(null);
  const [isRunningSandbox, setIsRunningSandbox] = useState(false);

  const [rawReportInput, setRawReportInput] = useState('');
  const [auditResult, setAuditResult] = useState<{
    ok: boolean;
    violations: string[];
    evidenceOrigin?: string;
  } | null>(null);
  const [isAuditingReport, setIsAuditingReport] = useState(false);

  const [validatedReport, setValidatedReport] = useState<SanitizedStage0Report | null>(null);
  const [priorities, setPriorities] = useState<AdapterPriorityScore[]>([]);
  const [workflowWeights, setWorkflowWeights] = useState<
    Record<VendorEcosystemId, WorkflowImportanceTier>
  >(DEFAULT_WORKFLOW_WEIGHTS);

  useEffect(() => {
    document.documentElement.classList.toggle('dark', isDark);
  }, [isDark]);

  const validateAndGenerateScripts = useCallback(
    async (cfgOverride?: Stage0Config, manifestOverride?: External86Manifest) => {
      setIsValidatingConfig(true);
      try {
        const res = await fetch('/api/stage0/validate-and-generate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            config: cfgOverride ?? config,
            manifest: manifestOverride ?? manifest,
          }),
        });
        const data = await res.json();
        setValidationState(data);
      } catch (err) {
        setValidationState({
          ok: false,
          failClosedCode: 'FAIL_CLOSED_CONFIG',
          detailCode: 'NETWORK_ERROR',
          message: err instanceof Error ? err.message : 'Request failed',
        });
      } finally {
        setIsValidatingConfig(false);
      }
    },
    [config, manifest]
  );

  useEffect(() => {
    validateAndGenerateScripts(DEFAULT_NTFS_STAGE0_CONFIG, DEFAULT_EXTERNAL_86_MANIFEST);
  }, []);

  const runSandboxVerification = async () => {
    setIsRunningSandbox(true);
    setActiveView('sandbox');
    try {
      const res = await fetch('/api/stage0/verify-sandbox', { method: 'POST' });
      const data = await res.json();
      if (data.ok && data.summary) {
        setSandboxSummary(data.summary);
      }
    } finally {
      setIsRunningSandbox(false);
    }
  };

  const validateReportPayload = async (
    rawOverride?: string,
    weightsOverride?: Record<VendorEcosystemId, WorkflowImportanceTier>
  ) => {
    const textToParse = rawOverride ?? rawReportInput;
    if (!textToParse.trim()) return;

    let parsed: unknown;
    try {
      parsed = JSON.parse(textToParse);
    } catch (err) {
      setAuditResult({
        ok: false,
        violations: [
          `JSON_SYNTAX_ERROR: ${err instanceof Error ? err.message : 'Invalid JSON'}`,
        ],
      });
      return;
    }

    setIsAuditingReport(true);
    try {
      const res = await fetch('/api/stage0/validate-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          candidateReport: parsed,
          workflowWeights: weightsOverride ?? workflowWeights,
        }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        setAuditResult({
          ok: false,
          violations: data.audit?.violations ?? ['REPORT_REJECTED'],
        });
        return;
      }

      setAuditResult({
        ok: true,
        violations: [],
        evidenceOrigin: data.report.evidenceOrigin,
      });
      setValidatedReport(data.report);
      setPriorities(data.priorities);
    } finally {
      setIsAuditingReport(false);
    }
  };

  const handleLoadSandboxReportIntoAdr = async (summary: SandboxVerificationSummary) => {
    const formatted = JSON.stringify(summary.generatedReport, null, 2);
    setRawReportInput(formatted);
    await validateReportPayload(formatted, workflowWeights);
    setActiveView('adr');
  };

  const handleLoadSyntheticIntoAdr = async () => {
    const formatted = JSON.stringify(SYNTHETIC_VALID_STAGE0_FIXTURE, null, 2);
    setRawReportInput(formatted);
    await validateReportPayload(formatted, workflowWeights);
    setActiveView('adr');
  };

  const handleChangeWorkflowWeight = async (
    eco: VendorEcosystemId,
    tier: WorkflowImportanceTier
  ) => {
    const nextWeights = { ...workflowWeights, [eco]: tier };
    setWorkflowWeights(nextWeights);
    if (validatedReport) {
      await validateReportPayload(JSON.stringify(validatedReport), nextWeights);
    }
  };

  const applyPreset = (preset: 'NTFS' | 'POSIX') => {
    const nextConfig =
      preset === 'NTFS' ? DEFAULT_NTFS_STAGE0_CONFIG : DEFAULT_POSIX_STAGE0_CONFIG;
    const nextManifest: External86Manifest =
      preset === 'NTFS'
        ? DEFAULT_EXTERNAL_86_MANIFEST
        : {
            ...DEFAULT_EXTERNAL_86_MANIFEST,
            rules: [
              {
                ruleId: 'R86_CLIENT_VAULT_01',
                kind: 'PATH_PREFIX',
                targetValue: '/srv/ai-archives/authorized-sessions/excluded-vault-86',
                reasonCode: 'OWNER_REVOKED_SCOPE',
              },
              DEFAULT_EXTERNAL_86_MANIFEST.rules[1],
              DEFAULT_EXTERNAL_86_MANIFEST.rules[2],
            ],
          };
    setConfig(nextConfig);
    setManifest(nextManifest);
    validateAndGenerateScripts(nextConfig, nextManifest);
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 text-slate-900 dark:bg-[#0B1120] dark:text-slate-100">
      {/* Strict 3-Zone Top Bar Contract */}
      <header className="flex items-center justify-between gap-8 px-6 py-3.5 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0B1120]">
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            setActiveView('config');
          }}
          className="text-base font-bold tracking-tight text-slate-900 dark:text-slate-100 whitespace-nowrap shrink-0 font-display"
        >
          Chronos Ledger
        </a>

        <nav
          aria-label="Stage 0 navigation"
          className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-600 dark:text-slate-400"
        >
          <button
            type="button"
            onClick={() => setActiveView('config')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeView === 'config'
                ? 'border-sky-500 text-slate-900 dark:text-slate-100'
                : 'border-transparent hover:text-slate-900 dark:hover:text-slate-200'
            }`}
          >
            Config &amp; Scripts
          </button>
          <button
            type="button"
            onClick={() => setActiveView('sandbox')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeView === 'sandbox'
                ? 'border-sky-500 text-slate-900 dark:text-slate-100'
                : 'border-transparent hover:text-slate-900 dark:hover:text-slate-200'
            }`}
          >
            Sandbox Syscall Audit
          </button>
          <button
            type="button"
            onClick={() => setActiveView('sanitizer')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeView === 'sanitizer'
                ? 'border-sky-500 text-slate-900 dark:text-slate-100'
                : 'border-transparent hover:text-slate-900 dark:hover:text-slate-200'
            }`}
          >
            Report Sanitizer
          </button>
          <button
            type="button"
            onClick={() => setActiveView('adr')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeView === 'adr'
                ? 'border-sky-500 text-slate-900 dark:text-slate-100'
                : 'border-transparent hover:text-slate-900 dark:hover:text-slate-200'
            }`}
          >
            Priority &amp; Reuse ADR
          </button>
        </nav>

        <div className="flex items-center shrink-0">
          <button
            type="button"
            onClick={runSandboxVerification}
            disabled={isRunningSandbox}
            className="px-4 py-2 text-xs font-medium bg-sky-600 hover:bg-sky-500 text-white rounded-md transition-colors disabled:opacity-50 whitespace-nowrap shrink-0"
          >
            {isRunningSandbox ? 'Running Audit...' : 'Run Syscall Verification'}
          </button>
        </div>
      </header>

      {/* Mobile View Navigation Strip */}
      <div className="flex md:hidden items-center gap-2 px-4 py-2.5 border-b border-slate-200 dark:border-slate-800 overflow-x-auto bg-white dark:bg-[#111827]">
        {(
          [
            ['config', 'Config & Scripts'],
            ['sandbox', 'Syscall Audit'],
            ['sanitizer', 'Sanitizer'],
            ['adr', 'Priority ADR'],
          ] as Array<[ActiveView, string]>
        ).map(([id, label]) => (
          <button
            key={id}
            type="button"
            onClick={() => setActiveView(id)}
            className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap shrink-0 ${
              activeView === id
                ? 'bg-sky-600 text-white'
                : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Main Workspace: 260px Sidebar + Primary Content Viewport */}
      <div className="flex-1 flex flex-col lg:flex-row">
        <aside
          aria-label="Stage 0 approval boundary and presets"
          className="w-full lg:w-[268px] shrink-0 border-b lg:border-b-0 lg:border-r border-slate-200 dark:border-slate-800 bg-white dark:bg-[#111827] p-5 space-y-6"
        >
          <div className="space-y-3">
            <h2 className="text-xs font-semibold text-slate-900 dark:text-slate-100 tracking-tight">
              Owner Approval Boundary
            </h2>
            <dl className="space-y-2.5 text-xs">
              <div className="flex items-baseline justify-between gap-2">
                <dt className="text-slate-500 dark:text-slate-400">Authorized Stage</dt>
                <dd className="font-mono font-medium text-sky-700 dark:text-sky-400">
                  STAGE_0_ONLY
                </dd>
              </div>
              <div className="flex items-baseline justify-between gap-2">
                <dt className="text-slate-500 dark:text-slate-400">Stage 1 Pipeline</dt>
                <dd className="font-mono text-slate-700 dark:text-slate-300">LOCKED</dd>
              </div>
              <div className="flex items-baseline justify-between gap-2">
                <dt className="text-slate-500 dark:text-slate-400">Dell Workstation</dt>
                <dd className="font-mono font-medium text-amber-700 dark:text-amber-400">
                  UNINSPECTED
                </dd>
              </div>
              <div className="flex items-baseline justify-between gap-2">
                <dt className="text-slate-500 dark:text-slate-400">Vendor Adapters</dt>
                <dd className="font-mono text-amber-700 dark:text-amber-400">ALL UNVERIFIED</dd>
              </div>
              <div className="flex items-baseline justify-between gap-2">
                <dt className="text-slate-500 dark:text-slate-400">External Spend</dt>
                <dd className="font-mono text-emerald-700 dark:text-emerald-400 tabular-nums">
                  $0.00 CEILING
                </dd>
              </div>
            </dl>
          </div>

          <div className="pt-5 border-t border-slate-200 dark:border-slate-800 space-y-2.5">
            <h2 className="text-xs font-semibold text-slate-900 dark:text-slate-100 tracking-tight">
              Host Security Spec Presets
            </h2>
            <div className="grid grid-cols-1 gap-2">
              <button
                type="button"
                onClick={() => applyPreset('NTFS')}
                className={`px-3 py-2 text-left text-xs rounded-md border transition-colors ${
                  config.hostOsMode === 'WINDOWS_NTFS'
                    ? 'border-sky-500 bg-sky-50/70 dark:bg-sky-950/30 text-slate-900 dark:text-slate-100 font-medium'
                    : 'border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800/50'
                }`}
              >
                Windows NTFS Workstation
              </button>
              <button
                type="button"
                onClick={() => applyPreset('POSIX')}
                className={`px-3 py-2 text-left text-xs rounded-md border transition-colors ${
                  config.hostOsMode === 'POSIX'
                    ? 'border-sky-500 bg-sky-50/70 dark:bg-sky-950/30 text-slate-900 dark:text-slate-100 font-medium'
                    : 'border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800/50'
                }`}
              >
                POSIX / Native WSL2 ext4
              </button>
            </div>
          </div>

          <div className="pt-5 border-t border-slate-200 dark:border-slate-800 space-y-2.5">
            <h2 className="text-xs font-semibold text-slate-900 dark:text-slate-100 tracking-tight">
              Display Posture
            </h2>
            <button
              type="button"
              onClick={() => setIsDark((prev) => !prev)}
              className="w-full inline-flex items-center justify-between px-3 py-2 text-xs font-medium border border-slate-200 dark:border-slate-800 rounded-md text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
            >
              <span>{isDark ? 'Dark Slate Console' : 'Light Archival Paper'}</span>
              {isDark ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
            </button>
          </div>
        </aside>

        <main className="flex-1 p-6 lg:p-8 max-w-6xl">
          {activeView === 'config' && (
            <ConfigAndScriptsPanel
              config={config}
              manifest={manifest}
              onChangeConfig={setConfig}
              onChangeManifest={setManifest}
              validationState={validationState}
              isValidating={isValidatingConfig}
              onValidateAndGenerate={() => validateAndGenerateScripts()}
            />
          )}

          {activeView === 'sandbox' && (
            <SandboxVerificationPanel
              summary={sandboxSummary}
              isRunning={isRunningSandbox}
              onRunVerification={runSandboxVerification}
              onLoadSandboxReportIntoAdr={handleLoadSandboxReportIntoAdr}
            />
          )}

          {activeView === 'sanitizer' && (
            <ReportSanitizerPanel
              rawReportInput={rawReportInput}
              onChangeRawInput={setRawReportInput}
              auditResult={auditResult}
              isAuditing={isAuditingReport}
              onValidateReportJson={validateReportPayload}
              onNavigateToAdr={() => setActiveView('adr')}
            />
          )}

          {activeView === 'adr' && (
            <PriorityAndReuseAdrPanel
              validatedReport={validatedReport}
              priorities={priorities}
              workflowWeights={workflowWeights}
              onChangeWorkflowWeight={handleChangeWorkflowWeight}
              onLoadSyntheticPreview={handleLoadSyntheticIntoAdr}
            />
          )}
        </main>
      </div>
    </div>
  );
}
