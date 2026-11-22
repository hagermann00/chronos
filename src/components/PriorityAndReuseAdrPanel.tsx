import { AlertTriangle, Database, HardDrive, Layers } from 'lucide-react';
import React from 'react';
import type {
  AdapterPriorityScore,
  SanitizedStage0Report,
  VendorEcosystemId,
  WorkflowImportanceTier,
} from '../stage0/types.ts';

interface PriorityAndReuseAdrPanelProps {
  validatedReport: SanitizedStage0Report | null;
  priorities: AdapterPriorityScore[];
  workflowWeights: Record<VendorEcosystemId, WorkflowImportanceTier>;
  onChangeWorkflowWeight: (eco: VendorEcosystemId, tier: WorkflowImportanceTier) => void;
  onLoadSyntheticPreview: () => void;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export const PriorityAndReuseAdrPanel: React.FC<PriorityAndReuseAdrPanelProps> = ({
  validatedReport,
  priorities,
  workflowWeights,
  onChangeWorkflowWeight,
  onLoadSyntheticPreview,
}) => {
  return (
    <div className="space-y-8">
      <div className="flex flex-col gap-2 pb-5 border-b border-slate-200 dark:border-slate-800">
        <div className="text-xs text-slate-500 dark:text-slate-400">
          <span>04. Post-Stage-0 Decision Gate Preview</span>
          <span className="mx-2" aria-hidden="true">·</span>
          <span>4-Factor Adapter Ranking</span>
          <span className="mx-2" aria-hidden="true">·</span>
          <span>Stage 1 Implementation Remains Locked</span>
        </div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100">
          Reuse Assessment &amp; Four-Factor Empirical Adapter Priority Matrix
        </h1>
        <p className="text-sm text-slate-600 dark:text-slate-400 max-w-3xl leading-relaxed">
          Evaluates Universal Harness &amp; SQLite schema reuse alongside the four-factor adapter
          priority score (Observed Usable Volume, Owner Workflow Importance, Format Accessibility
          &amp; Cleanliness, and Implementation/Reuse Cost). All adapters remain{' '}
          <code className="font-mono text-xs">UNVERIFIED</code> until real owner samples are tested
          in Stage 1.
        </p>
      </div>

      {!validatedReport ? (
        <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#111827] rounded-lg p-10 text-center space-y-4">
          <AlertTriangle className="w-8 h-8 text-amber-500 mx-auto" />
          <div className="space-y-1.5 max-w-xl mx-auto">
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              Target Dell Workstation Status: UNINSPECTED (Zero Evidence Collected)
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
              No sanitized Stage 0 workstation report has been loaded yet. Run the Stage 0 probe on
              your workstation and upload the sanitized JSON in <strong>Report Sanitizer</strong>,
              or preview the scoring matrix using an explicitly labeled synthetic fixture.
            </p>
          </div>
          <button
            type="button"
            onClick={onLoadSyntheticPreview}
            className="px-4 py-2 text-xs font-medium border border-slate-300 dark:border-slate-700 rounded-md text-slate-800 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
          >
            Preview Matrix with Synthetic Fixture (Non-Workstation Data)
          </button>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Explicit Provenance Attribution Banner */}
          <div className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#111827] rounded-lg p-5 flex flex-wrap items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="text-xs font-mono text-amber-700 dark:text-amber-400 font-medium">
                EVIDENCE ORIGIN: {validatedReport.evidenceOrigin}
                {validatedReport.evidenceOrigin !== 'WORKSTATION_IMPORTED_REPORT'
                  ? ' — NOT TARGET DELL WORKSTATION EVIDENCE'
                  : ' — USER-UPLOADED SANITIZED REPORT'}
              </div>
              <div className="text-xs text-slate-600 dark:text-slate-400 font-mono">
                <span>Generated: {validatedReport.generatedAtIso}</span>
                <span className="mx-2" aria-hidden="true">·</span>
                <span>Manifest: {validatedReport.securityAudit.manifestId}</span>
                <span className="mx-2" aria-hidden="true">·</span>
                <span>Reuse Verdict Code: {validatedReport.reuseInventory.reuseAssessmentCode}</span>
              </div>
            </div>
          </div>

          {/* Host Hardware & Existing Reuse Cards */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-stretch">
            <section
              aria-labelledby="host-gpu-heading"
              className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#111827] rounded-lg p-6 space-y-4"
            >
              <div className="flex items-center gap-2 text-slate-900 dark:text-slate-100 font-semibold text-base">
                <HardDrive className="w-4 h-4 text-sky-500" />
                <h2 id="host-gpu-heading">Host, Filesystem &amp; llama.cpp GPU Readiness</h2>
              </div>
              <dl className="grid grid-cols-2 gap-y-3 gap-x-4 text-xs">
                <div>
                  <dt className="text-slate-500 dark:text-slate-400">OS / Kernel</dt>
                  <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5">
                    {validatedReport.hostProfile.osPlatform} ({validatedReport.hostProfile.osRelease})
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500 dark:text-slate-400">CPU &amp; Memory</dt>
                  <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5 tabular-nums">
                    {validatedReport.hostProfile.cpuCores} Cores ·{' '}
                    {formatBytes(validatedReport.hostProfile.totalMemBytes)} RAM
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500 dark:text-slate-400">GPU / VRAM Detection</dt>
                  <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5 tabular-nums">
                    {validatedReport.hostProfile.gpuSummary.detectionState}
                    {validatedReport.hostProfile.gpuSummary.devices.length > 0 &&
                      ` (${validatedReport.hostProfile.gpuSummary.devices
                        .map((d) => `${d.modelCode}: ${d.vramFreeMb}/${d.vramTotalMb} MB`)
                        .join(', ')})`}
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500 dark:text-slate-400">llama.cpp &amp; GGUF Headers</dt>
                  <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5 tabular-nums">
                    server={String(validatedReport.hostProfile.llamaCppStatus.serverBinaryPresent)} ·
                    GGUFs={validatedReport.hostProfile.llamaCppStatus.ggufHeaderCount}
                  </dd>
                </div>
                <div className="col-span-2">
                  <dt className="text-slate-500 dark:text-slate-400">Allowlisted Roots &amp; Modes</dt>
                  <dd className="font-mono text-slate-900 dark:text-slate-100 mt-0.5">
                    {validatedReport.hostProfile.rootFilesystems
                      .map((r) => `${r.rootAlias} (${r.fsMode})`)
                      .join(' · ')}
                  </dd>
                </div>
              </dl>
            </section>

            <section
              aria-labelledby="reuse-ddl-heading"
              className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#111827] rounded-lg p-6 space-y-4"
            >
              <div className="flex items-center gap-2 text-slate-900 dark:text-slate-100 font-semibold text-base">
                <Database className="w-4 h-4 text-sky-500" />
                <h2 id="reuse-ddl-heading">
                  Universal Harness &amp; Immutable SQLite DDL Inventory
                </h2>
              </div>
              <div className="text-xs text-slate-600 dark:text-slate-300 font-mono">
                <span>
                  Universal Harness Detected:{' '}
                  {String(validatedReport.reuseInventory.universalHarnessDetected)} (
                  {validatedReport.reuseInventory.universalHarnessEntrypointsCount} entrypoints)
                </span>
                <span className="mx-2" aria-hidden="true">·</span>
                <span>Zone A Write Violations: {validatedReport.securityAudit.zoneAWriteViolations}</span>
              </div>

              {validatedReport.reuseInventory.sqliteLedgersInspected.length === 0 ? (
                <div className="text-xs text-slate-500 dark:text-slate-400">
                  Zero SQLite ledgers observed inside allowlisted roots.
                </div>
              ) : (
                <div className="divide-y divide-slate-200 dark:divide-slate-800 border-t border-slate-200 dark:border-slate-800">
                  {validatedReport.reuseInventory.sqliteLedgersInspected.map((tbl, idx) => (
                    <div
                      key={`${tbl.ledgerAlias}-${tbl.tableName}-${idx}`}
                      className="py-3 text-xs font-mono space-y-1"
                    >
                      <div className="text-slate-900 dark:text-slate-100 font-medium">
                        {tbl.ledgerAlias} · {tbl.tableName}{' '}
                        <span className="text-slate-500 font-normal">
                          (immutable_ro={String(tbl.openedImmutableReadOnly)})
                        </span>
                      </div>
                      <div className="text-slate-600 dark:text-slate-400">
                        Columns:{' '}
                        {tbl.columns.map((c) => `${c.name}:${c.declaredType}`).join(', ')}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>
          </div>

          {/* 4-Factor Adapter Prioritization Matrix */}
          <section
            aria-labelledby="priority-matrix-heading"
            className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#111827] rounded-lg overflow-hidden"
          >
            <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-3">
              <div>
                <div className="flex items-center gap-2">
                  <Layers className="w-4 h-4 text-sky-500" />
                  <h2
                    id="priority-matrix-heading"
                    className="text-base font-semibold text-slate-900 dark:text-slate-100"
                  >
                    Four-Factor Empirical Adapter Prioritization (All Formats Strictly UNVERIFIED)
                  </h2>
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  Adjust Owner Workflow Importance per ecosystem to recalculate composite rankings
                  without relying on raw file counts alone.
                </p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400">
                    <th className="py-3 px-5 font-medium">Rank &amp; Ecosystem</th>
                    <th className="py-3 px-3 font-medium">Status</th>
                    <th className="py-3 px-3 font-medium text-right">Usable Data</th>
                    <th className="py-3 px-3 font-medium">Owner Workflow Weight</th>
                    <th className="py-3 px-3 font-medium text-right">
                      Vol / Wkf / Acc / Reuse
                    </th>
                    <th className="py-3 px-5 font-medium text-right">Composite</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800/70 text-xs">
                  {priorities.map((row, idx) => (
                    <tr
                      key={row.ecosystem}
                      className="hover:bg-slate-50 dark:hover:bg-slate-800/40"
                    >
                      <td className="py-3 px-5">
                        <div className="font-medium text-slate-900 dark:text-slate-100">
                          {String(idx + 1).padStart(2, '0')}. {row.displayName}
                        </div>
                        <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                          {row.rationale}
                        </div>
                      </td>
                      <td className="py-3 px-3 font-mono text-amber-700 dark:text-amber-400 whitespace-nowrap">
                        {row.verificationStatus}
                      </td>
                      <td className="py-3 px-3 font-mono text-right text-slate-700 dark:text-slate-300 tabular-nums whitespace-nowrap">
                        <div>{formatBytes(row.usableBytes)}</div>
                        <div className="text-[11px] text-slate-500">
                          {row.usableFileCount} file(s)
                        </div>
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap">
                        <label htmlFor={`wf-select-${row.ecosystem}`} className="sr-only">
                          Workflow importance for {row.displayName}
                        </label>
                        <select
                          id={`wf-select-${row.ecosystem}`}
                          value={workflowWeights[row.ecosystem] ?? row.workflowTier}
                          onChange={(e) =>
                            onChangeWorkflowWeight(
                              row.ecosystem,
                              e.target.value as WorkflowImportanceTier
                            )
                          }
                          className="px-2 py-1 text-xs font-mono bg-slate-50 dark:bg-[#0B1120] border border-slate-300 dark:border-slate-700 rounded text-slate-900 dark:text-slate-100"
                        >
                          <option value="CRITICAL_ACTIVE_WORK">CRITICAL_ACTIVE_WORK</option>
                          <option value="HIGH_REFERENCE">HIGH_REFERENCE</option>
                          <option value="ARCHIVAL_LOW">ARCHIVAL_LOW</option>
                        </select>
                      </td>
                      <td className="py-3 px-3 font-mono text-right text-slate-600 dark:text-slate-400 tabular-nums whitespace-nowrap">
                        {row.volumeScore} / {row.workflowScore} / {row.accessibilityScore} /{' '}
                        {row.implementationReuseScore}
                      </td>
                      <td className="py-3 px-5 font-mono font-semibold text-right text-sky-700 dark:text-sky-400 tabular-nums whitespace-nowrap">
                        {row.compositeScore} / 100
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      )}
    </div>
  );
};
