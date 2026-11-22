import { CheckCircle2, Play, ShieldCheck, XCircle } from 'lucide-react';
import React from 'react';
import type { SandboxVerificationSummary } from '../stage0/sandboxVerifier.ts';

interface SandboxVerificationPanelProps {
  summary: SandboxVerificationSummary | null;
  isRunning: boolean;
  onRunVerification: () => void;
  onLoadSandboxReportIntoAdr: (summary: SandboxVerificationSummary) => void;
}

export const SandboxVerificationPanel: React.FC<SandboxVerificationPanelProps> = ({
  summary,
  isRunning,
  onRunVerification,
  onLoadSandboxReportIntoAdr,
}) => {
  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-end justify-between gap-4 pb-5 border-b border-slate-200 dark:border-slate-800">
        <div className="space-y-2">
          <div className="text-xs text-slate-500 dark:text-slate-400">
            <span>02. Real Syscall &amp; Canary Proof</span>
            <span className="mx-2" aria-hidden="true">·</span>
            <span>Isolated Container /tmp Scratch Dir</span>
            <span className="mx-2" aria-hidden="true">·</span>
            <span>Does Not Represent Dell Workstation</span>
          </div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100">
            Live Scratch-Sandbox Syscall &amp; Multi-Identity Canary Audit
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-400 max-w-3xl leading-relaxed">
            Executes real kernel syscalls (<code className="font-mono text-xs">lstat</code>,{' '}
            <code className="font-mono text-xs">symlink</code>,{' '}
            <code className="font-mono text-xs">link</code>,{' '}
            <code className="font-mono text-xs">chmod 0000</code>, subprocess{' '}
            <code className="font-mono text-xs">cat/ls/grep</code>, ZIP Central Directory binary
            reads, and immutable SQLite <code className="font-mono text-xs">mode=ro&amp;immutable=1</code>{' '}
            inspection) inside a disposable scratch directory.
          </p>
        </div>

        <button
          type="button"
          onClick={onRunVerification}
          disabled={isRunning}
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-800 dark:text-slate-200 rounded-md transition-colors disabled:opacity-50 whitespace-nowrap shrink-0"
        >
          <Play className="w-3.5 h-3.5" />
          {isRunning ? 'Executing Syscall Suite...' : 'Re-Run Scratch Syscall Suite'}
        </button>
      </div>

      {!summary ? (
        <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#111827] rounded-lg p-10 text-center space-y-3">
          <ShieldCheck className="w-8 h-8 text-slate-400 mx-auto" />
          <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            No Sandbox Syscall Run Recorded in This Session
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 max-w-lg mx-auto">
            Click <strong>Execute Scratch Syscall Suite</strong> to construct real symlinks,
            hardlink inode aliases, mixed ZIP archives, read-only SQLite ledgers, and subprocess
            canary probes inside an isolated temporary directory.
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Summary Banner */}
          <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#111827] rounded-lg p-5 flex flex-wrap items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="text-xs font-mono text-slate-500 dark:text-slate-400">
                <span>ORIGIN: {summary.environmentBanner}</span>
                <span className="mx-2" aria-hidden="true">·</span>
                <span>EXECUTED: {summary.executedAtIso}</span>
              </div>
              <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                {summary.allPassed
                  ? `All ${summary.checks.length}/${summary.checks.length} Real-Syscall Boundary Checks Passed`
                  : 'One or more syscall verification checks failed'}
              </div>
            </div>

            <button
              type="button"
              onClick={() => onLoadSandboxReportIntoAdr(summary)}
              className="px-3.5 py-2 text-xs font-medium border border-slate-300 dark:border-slate-700 rounded-md text-slate-800 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
            >
              Inspect Generated Scratch Report in ADR View
            </button>
          </div>

          {/* 6 Verification Checks Table */}
          <section
            aria-labelledby="syscall-checks-heading"
            className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#111827] rounded-lg overflow-hidden"
          >
            <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800">
              <h2
                id="syscall-checks-heading"
                className="text-base font-semibold text-slate-900 dark:text-slate-100"
              >
                Measured Syscall &amp; Quarantine Assertions
              </h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400">
                    <th className="py-3 px-6 font-medium">Status</th>
                    <th className="py-3 px-4 font-medium">Check Identifier &amp; Assertion</th>
                    <th className="py-3 px-6 font-medium">Measured Evidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800/70 text-xs">
                  {summary.checks.map((chk) => (
                    <tr
                      key={chk.checkId}
                      className="hover:bg-slate-50 dark:hover:bg-slate-800/40"
                    >
                      <td className="py-3.5 px-6 whitespace-nowrap">
                        {chk.passed ? (
                          <span className="inline-flex items-center gap-1.5 font-mono font-medium text-emerald-700 dark:text-emerald-400">
                            <CheckCircle2 className="w-4 h-4" />
                            PASS
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 font-mono font-medium text-rose-700 dark:text-rose-400">
                            <XCircle className="w-4 h-4" />
                            FAIL
                          </span>
                        )}
                      </td>
                      <td className="py-3.5 px-4">
                        <div className="font-medium text-slate-900 dark:text-slate-100">
                          {chk.title}
                        </div>
                        <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                          {chk.checkId}
                        </div>
                      </td>
                      <td className="py-3.5 px-6 font-mono text-slate-700 dark:text-slate-300">
                        {chk.measuredDetail}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          {/* Multi-Identity Canary Results Matrix */}
          <section
            aria-labelledby="canary-matrix-heading"
            className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#111827] rounded-lg overflow-hidden"
          >
            <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800">
              <h2
                id="canary-matrix-heading"
                className="text-base font-semibold text-slate-900 dark:text-slate-100"
              >
                Live Subprocess Canary Access-Control Matrix (Non-Sensitive Synthetic Canary)
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Demonstrates empirically why application-level 86 rules alone do not stop same-UID
                CLI agents unless paired with OS ACL / UID / mount-namespace isolation.
              </p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400">
                    <th className="py-3 px-6 font-medium">Execution Principal</th>
                    <th className="py-3 px-4 font-medium">Probes Executed</th>
                    <th className="py-3 px-4 font-medium">Empirical Kernel Outcome</th>
                    <th className="py-3 px-6 font-medium">Architectural Remediation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800/70 text-xs">
                  {summary.generatedReport.securityAudit.multiIdentityCanaryResults.map(
                    (c, idx) => (
                      <tr
                        key={idx}
                        className="hover:bg-slate-50 dark:hover:bg-slate-800/40"
                      >
                        <td className="py-3.5 px-6 font-medium text-slate-900 dark:text-slate-100">
                          <div>{c.identityLabel}</div>
                          <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                            {c.principalKind}
                          </div>
                        </td>
                        <td className="py-3.5 px-4 font-mono text-slate-600 dark:text-slate-300 whitespace-nowrap">
                          {c.probeOperationsTested.join(' · ')}
                        </td>
                        <td className="py-3.5 px-4 font-mono whitespace-nowrap">
                          <span
                            className={
                              c.outcome === 'FAIL_EXPOSED_TO_IDENTITY'
                                ? 'text-amber-700 dark:text-amber-400 font-medium'
                                : 'text-emerald-700 dark:text-emerald-400 font-medium'
                            }
                          >
                            {c.outcome}
                          </span>
                          <div className="text-[11px] text-slate-500 dark:text-slate-400">
                            {c.osErrorCode}
                          </div>
                        </td>
                        <td className="py-3.5 px-6 text-slate-600 dark:text-slate-300">
                          {c.remediationNote}
                        </td>
                      </tr>
                    )
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      )}
    </div>
  );
};
