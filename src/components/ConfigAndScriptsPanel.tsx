import { Check, Copy, Download, FileCode2, Plus, ShieldAlert, Trash2 } from 'lucide-react';
import React, { useState } from 'react';
import type {
  External86Manifest,
  OsPlatformMode,
  Rule86Entry,
  Rule86Kind,
  ScanRootEntry,
  Stage0Config,
} from '../stage0/types.ts';

interface ConfigAndScriptsPanelProps {
  config: Stage0Config;
  manifest: External86Manifest;
  onChangeConfig: (next: Stage0Config) => void;
  onChangeManifest: (next: External86Manifest) => void;
  validationState: {
    ok: boolean;
    failClosedCode?: string;
    detailCode?: string;
    message?: string;
    normalizedRootCount?: number;
    normalizedZoneBKey?: string;
    scripts?: { probeScriptMjs: string; canaryScriptMjs: string };
  } | null;
  isValidating: boolean;
  onValidateAndGenerate: () => void;
}

const RULE_KINDS: Rule86Kind[] = [
  'PATH_PREFIX',
  'FILENAME_EXACT',
  'GLOB_SEGMENT',
  'ARCHIVE_ENTRY_NAME',
  'REVOKED_CONVERSATION_ID',
  'KNOWN_MIXED_CONTAINER',
  'POSIX_DEV_INO',
  'NTFS_FILE_ID_128',
];

export const ConfigAndScriptsPanel: React.FC<ConfigAndScriptsPanelProps> = ({
  config,
  manifest,
  onChangeConfig,
  onChangeManifest,
  validationState,
  isValidating,
  onValidateAndGenerate,
}) => {
  const [newAlias, setNewAlias] = useState('ROOT_03');
  const [newRootPath, setNewRootPath] = useState('');
  const [newRuleId, setNewRuleId] = useState('R86_CUSTOM_04');
  const [newRuleKind, setNewRuleKind] = useState<Rule86Kind>('PATH_PREFIX');
  const [newRuleTarget, setNewRuleTarget] = useState('');
  const [activeScriptTab, setActiveScriptTab] = useState<'probe' | 'canary' | 'configJson'>('probe');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleAddRoot = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newAlias.trim() || !newRootPath.trim()) return;
    const entry: ScanRootEntry = {
      alias: newAlias.trim().toUpperCase(),
      absolutePath: newRootPath.trim(),
      expectedFsMode: config.hostOsMode,
      ntfsCaseSensitiveDir: false,
    };
    onChangeConfig({
      ...config,
      scanRootsAllowlist: [...config.scanRootsAllowlist, entry],
    });
    const nextNum = config.scanRootsAllowlist.length + 2;
    setNewAlias(`ROOT_${String(nextNum).padStart(2, '0')}`);
    setNewRootPath('');
  };

  const handleRemoveRoot = (alias: string) => {
    onChangeConfig({
      ...config,
      scanRootsAllowlist: config.scanRootsAllowlist.filter((r) => r.alias !== alias),
    });
  };

  const handleAddRule = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRuleId.trim() || !newRuleTarget.trim()) return;
    const nextRule: Rule86Entry = {
      ruleId: newRuleId.trim(),
      kind: newRuleKind,
      targetValue: newRuleTarget.trim(),
      reasonCode: 'OWNER_SPECIFIED_EXCLUSION',
    };
    onChangeManifest({
      ...manifest,
      rules: [...manifest.rules, nextRule],
    });
    setNewRuleId(`R86_CUSTOM_${String(manifest.rules.length + 2).padStart(2, '0')}`);
    setNewRuleTarget('');
  };

  const handleRemoveRule = (ruleId: string) => {
    onChangeManifest({
      ...manifest,
      rules: manifest.rules.filter((r) => r.ruleId !== ruleId),
    });
  };

  const handleCopy = async (key: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 1800);
    } catch {
      // Ignore clipboard failures in restricted contexts
    }
  };

  const handleDownloadFile = (filename: string, content: string) => {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const combinedConfigJson = JSON.stringify(
    { stage0Config: config, external86Manifest: manifest },
    null,
    2
  );

  const displayedCode =
    activeScriptTab === 'probe'
      ? validationState?.scripts?.probeScriptMjs ??
        'Validate configuration to generate stage0-workstation-probe.mjs.'
      : activeScriptTab === 'canary'
        ? validationState?.scripts?.canaryScriptMjs ??
          'Validate configuration to generate stage0-multi-identity-canary.mjs.'
        : combinedConfigJson;

  return (
    <div className="space-y-8">
      <div className="flex flex-col gap-2 pb-5 border-b border-slate-200 dark:border-slate-800">
        <div className="text-xs text-slate-500 dark:text-slate-400">
          <span>01. Pre-Traversal Contract</span>
          <span className="mx-2" aria-hidden="true">·</span>
          <span>Zone A Read-Only Inspection vs. Zone B Authorized Output</span>
          <span className="mx-2" aria-hidden="true">·</span>
          <span>Fail-Closed Path Normalization</span>
        </div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100">
          Scan-Root Allowlist, External 86 Manifest &amp; Workstation Scripts
        </h1>
        <p className="text-sm text-slate-600 dark:text-slate-400 max-w-3xl leading-relaxed">
          Stage 0 refuses to traverse any directory unless an explicit owner-approved{' '}
          <code className="text-xs px-1 py-0.5 bg-slate-100 dark:bg-slate-800 rounded">
            scanRootsAllowlist
          </code>{' '}
          and schema-verified{' '}
          <code className="text-xs px-1 py-0.5 bg-slate-100 dark:bg-slate-800 rounded">
            external86Manifest
          </code>{' '}
          are validated upfront, with Zone B output strictly disjoint from Zone A source roots.
        </p>
      </div>

      {/* Host Filesystem & Zone B Output Settings */}
      <section
        aria-labelledby="zone-boundary-heading"
        className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#111827] rounded-lg p-6 space-y-5"
      >
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2
              id="zone-boundary-heading"
              className="text-base font-semibold text-slate-900 dark:text-slate-100"
            >
              Host Filesystem Semantics &amp; Disjoint Zone B Output Target
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Windows NTFS enforces extended-length prefixes, ADS/UNC/reserved-device blocking, and
              junction/cloud-recall skipping; POSIX enforces O_NOFOLLOW and st_dev mount boundaries.
            </p>
          </div>

          <div
            role="group"
            aria-label="Target host filesystem specification"
            className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-800/80 rounded-lg"
          >
            {(['WINDOWS_NTFS', 'POSIX'] as OsPlatformMode[]).map((mode) => (
              <button
                key={mode}
                type="button"
                onClick={() =>
                  onChangeConfig({
                    ...config,
                    hostOsMode: mode,
                    scanRootsAllowlist: config.scanRootsAllowlist.map((r) => ({
                      ...r,
                      expectedFsMode: mode,
                    })),
                  })
                }
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                  config.hostOsMode === mode
                    ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-sky-300 shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                {mode === 'WINDOWS_NTFS' ? 'Windows NTFS Spec' : 'POSIX / WSL2 ext4 Spec'}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          <div>
            <label
              htmlFor="manifest-path-input"
              className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5"
            >
              External 86 Manifest File Path (Read-Only Input)
            </label>
            <input
              id="manifest-path-input"
              type="text"
              value={config.external86ManifestPath}
              onChange={(e) =>
                onChangeConfig({ ...config, external86ManifestPath: e.target.value })
              }
              className="w-full px-3 py-2 text-xs font-mono bg-slate-50 dark:bg-[#0B1120] border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-500"
            />
          </div>

          <div>
            <label
              htmlFor="zone-b-output-input"
              className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5"
            >
              Zone B Authorized Report Output Directory (Must Not Overlap Zone A)
            </label>
            <input
              id="zone-b-output-input"
              type="text"
              value={config.zoneBOutputDir}
              onChange={(e) => onChangeConfig({ ...config, zoneBOutputDir: e.target.value })}
              className="w-full px-3 py-2 text-xs font-mono bg-slate-50 dark:bg-[#0B1120] border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-sky-500"
            />
          </div>
        </div>
      </section>

      {/* Two-Column Grid: Zone A Scan Roots Allowlist + External 86 Manifest Rules */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 items-stretch">
        {/* Zone A Allowlist */}
        <section
          aria-labelledby="allowlist-heading"
          className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#111827] rounded-lg p-6 flex flex-col justify-between space-y-5"
        >
          <div className="space-y-4">
            <div>
              <h2
                id="allowlist-heading"
                className="text-base font-semibold text-slate-900 dark:text-slate-100"
              >
                Zone A — Owner-Approved Scan-Root Allowlist ({config.scanRootsAllowlist.length})
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Opaque aliases (<code className="font-mono">ROOT_01</code>) replace raw directory
                names in sanitized Stage 0 reports. Empty allowlist fails closed immediately.
              </p>
            </div>

            {config.scanRootsAllowlist.length === 0 ? (
              <div className="p-4 border border-amber-300 dark:border-amber-800/70 bg-amber-50/60 dark:bg-amber-950/20 rounded-md text-xs text-amber-800 dark:text-amber-300">
                Allowlist is currently empty. Precondition check will fail closed with{' '}
                <code className="font-mono">FAIL_CLOSED_CONFIG</code>.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400">
                      <th className="py-2 pr-3 font-medium">Opaque Alias</th>
                      <th className="py-2 px-3 font-medium">Absolute Path (Local Only)</th>
                      <th className="py-2 pl-3 text-right font-medium">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800/70 text-xs">
                    {config.scanRootsAllowlist.map((root) => (
                      <tr
                        key={root.alias}
                        className="hover:bg-slate-50 dark:hover:bg-slate-800/40"
                      >
                        <td className="py-2.5 pr-3 font-mono font-medium text-sky-700 dark:text-sky-400 whitespace-nowrap">
                          {root.alias}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-slate-700 dark:text-slate-300 break-all">
                          {root.absolutePath}
                        </td>
                        <td className="py-2.5 pl-3 text-right whitespace-nowrap">
                          <button
                            type="button"
                            aria-label={`Remove scan root ${root.alias}`}
                            onClick={() => handleRemoveRoot(root.alias)}
                            className="p-1.5 text-slate-400 hover:text-rose-600 dark:hover:text-rose-400 rounded transition-colors"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <form onSubmit={handleAddRoot} className="pt-4 border-t border-slate-200 dark:border-slate-800 space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              <div>
                <label htmlFor="new-root-alias" className="sr-only">
                  New Root Alias
                </label>
                <input
                  id="new-root-alias"
                  type="text"
                  placeholder="ROOT_03"
                  value={newAlias}
                  onChange={(e) => setNewAlias(e.target.value)}
                  className="w-full px-2.5 py-2 text-xs font-mono bg-slate-50 dark:bg-[#0B1120] border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
                />
              </div>
              <div className="sm:col-span-2 flex gap-2">
                <label htmlFor="new-root-path" className="sr-only">
                  New Scan Root Absolute Path
                </label>
                <input
                  id="new-root-path"
                  type="text"
                  placeholder={
                    config.hostOsMode === 'WINDOWS_NTFS'
                      ? 'D:\\Exports\\Gemini_CLI_Sessions'
                      : '/srv/exports/gemini-cli'
                  }
                  value={newRootPath}
                  onChange={(e) => setNewRootPath(e.target.value)}
                  className="flex-1 px-2.5 py-2 text-xs font-mono bg-slate-50 dark:bg-[#0B1120] border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
                />
                <button
                  type="submit"
                  className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium bg-slate-900 dark:bg-slate-800 text-white hover:bg-slate-800 dark:hover:bg-slate-700 rounded-md transition-colors whitespace-nowrap shrink-0"
                >
                  <Plus className="w-3.5 h-3.5" />
                  Add Root
                </button>
              </div>
            </div>
          </form>
        </section>

        {/* External 86 Manifest Rules */}
        <section
          aria-labelledby="manifest-rules-heading"
          className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#111827] rounded-lg p-6 flex flex-col justify-between space-y-5"
        >
          <div className="space-y-4">
            <div>
              <h2
                id="manifest-rules-heading"
                className="text-base font-semibold text-slate-900 dark:text-slate-100"
              >
                Verified External 86 Manifest Rules ({manifest.rules.length})
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Matched paths, inodes/FileIDs, and mixed archive entries are pruned before{' '}
                <code className="font-mono">open()</code>; sanitized reports emit only{' '}
                <code className="font-mono">ruleId</code> counts.
              </p>
            </div>

            {manifest.rules.length === 0 ? (
              <div className="p-4 border border-amber-300 dark:border-amber-800/70 bg-amber-50/60 dark:bg-amber-950/20 rounded-md text-xs text-amber-800 dark:text-amber-300">
                Zero 86 rules defined. Unless explicit empty-ruleset sign-off is checked, Stage 0
                aborts with <code className="font-mono">FAIL_CLOSED_86_INIT</code>.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400">
                      <th className="py-2 pr-3 font-medium">Rule &amp; Scope</th>
                      <th className="py-2 px-3 font-medium">Local Pattern (Never Exported)</th>
                      <th className="py-2 pl-2 text-right font-medium">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800/70 text-xs">
                    {manifest.rules.map((rule) => (
                      <tr
                        key={rule.ruleId}
                        className="hover:bg-slate-50 dark:hover:bg-slate-800/40"
                      >
                        <td className="py-2.5 pr-3 font-mono whitespace-nowrap">
                          <div className="font-medium text-slate-900 dark:text-slate-200">
                            {rule.ruleId}
                          </div>
                          <div className="text-[11px] text-slate-500 dark:text-slate-400">
                            {rule.kind}
                          </div>
                        </td>
                        <td className="py-2.5 px-3 font-mono text-slate-700 dark:text-slate-300 break-all">
                          {rule.targetValue}
                        </td>
                        <td className="py-2.5 pl-2 text-right whitespace-nowrap">
                          <button
                            type="button"
                            aria-label={`Remove 86 rule ${rule.ruleId}`}
                            onClick={() => handleRemoveRule(rule.ruleId)}
                            className="p-1.5 text-slate-400 hover:text-rose-600 dark:hover:text-rose-400 rounded transition-colors"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <form onSubmit={handleAddRule} className="pt-4 border-t border-slate-200 dark:border-slate-800 space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              <div>
                <label htmlFor="new-rule-id" className="sr-only">
                  New 86 Rule ID
                </label>
                <input
                  id="new-rule-id"
                  type="text"
                  placeholder="R86_004"
                  value={newRuleId}
                  onChange={(e) => setNewRuleId(e.target.value)}
                  className="w-full px-2.5 py-2 text-xs font-mono bg-slate-50 dark:bg-[#0B1120] border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
                />
              </div>
              <div className="sm:col-span-2">
                <label htmlFor="new-rule-kind" className="sr-only">
                  86 Rule Kind
                </label>
                <select
                  id="new-rule-kind"
                  value={newRuleKind}
                  onChange={(e) => setNewRuleKind(e.target.value as Rule86Kind)}
                  className="w-full px-2.5 py-2 text-xs font-mono bg-slate-50 dark:bg-[#0B1120] border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
                >
                  {RULE_KINDS.map((k) => (
                    <option key={k} value={k}>
                      {k}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div className="flex gap-2">
              <label htmlFor="new-rule-target" className="sr-only">
                86 Rule Target Pattern
              </label>
              <input
                id="new-rule-target"
                type="text"
                placeholder="Path prefix, filename, archive entry name, or revoked conversation ID"
                value={newRuleTarget}
                onChange={(e) => setNewRuleTarget(e.target.value)}
                className="flex-1 px-2.5 py-2 text-xs font-mono bg-slate-50 dark:bg-[#0B1120] border border-slate-300 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
              />
              <button
                type="submit"
                className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium bg-slate-900 dark:bg-slate-800 text-white hover:bg-slate-800 dark:hover:bg-slate-700 rounded-md transition-colors whitespace-nowrap shrink-0"
              >
                <Plus className="w-3.5 h-3.5" />
                Add 86 Rule
              </button>
            </div>
          </form>
        </section>
      </div>

      {/* Validation Outcome & Auditable Workstation Script Output */}
      <section
        aria-labelledby="workstation-scripts-heading"
        className="border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#111827] rounded-lg p-6 space-y-4"
      >
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2
              id="workstation-scripts-heading"
              className="text-base font-semibold text-slate-900 dark:text-slate-100"
            >
              Precondition Gate Result &amp; Auditable Stage 0 Scripts
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Verify path &amp; manifest rules before exporting zero-dependency scripts for your
              Dell workstation.
            </p>
          </div>

          <button
            type="button"
            onClick={onValidateAndGenerate}
            disabled={isValidating}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium bg-sky-600 hover:bg-sky-500 text-white rounded-md transition-colors disabled:opacity-50 whitespace-nowrap shrink-0"
          >
            <FileCode2 className="w-4 h-4" />
            {isValidating ? 'Validating Preconditions...' : 'Validate & Refresh Scripts'}
          </button>
        </div>

        {validationState && !validationState.ok && (
          <div
            role="alert"
            className="p-4 rounded-md border border-rose-300 dark:border-rose-800/80 bg-rose-50 dark:bg-rose-950/30 text-xs text-rose-800 dark:text-rose-300 flex items-start gap-3"
          >
            <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <div className="font-semibold font-mono">
                {validationState.failClosedCode} · {validationState.detailCode}
              </div>
              <div>{validationState.message}</div>
            </div>
          </div>
        )}

        {validationState && validationState.ok && (
          <div className="text-xs text-emerald-700 dark:text-emerald-400 font-mono">
            <span>PRECONDITIONS_VERIFIED</span>
            <span className="mx-2" aria-hidden="true">·</span>
            <span>Allowlisted Roots: {validationState.normalizedRootCount}</span>
            <span className="mx-2" aria-hidden="true">·</span>
            <span>Zone B Canonical Target: {validationState.normalizedZoneBKey}</span>
          </div>
        )}

        <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
          <div
            role="tablist"
            aria-label="Generated Stage 0 artifacts"
            className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-800/80 rounded-lg"
          >
            <button
              role="tab"
              aria-selected={activeScriptTab === 'probe'}
              type="button"
              onClick={() => setActiveScriptTab('probe')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                activeScriptTab === 'probe'
                  ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-sky-300 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
              }`}
            >
              stage0-workstation-probe.mjs
            </button>
            <button
              role="tab"
              aria-selected={activeScriptTab === 'canary'}
              type="button"
              onClick={() => setActiveScriptTab('canary')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                activeScriptTab === 'canary'
                  ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-sky-300 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
              }`}
            >
              stage0-multi-identity-canary.mjs
            </button>
            <button
              role="tab"
              aria-selected={activeScriptTab === 'configJson'}
              type="button"
              onClick={() => setActiveScriptTab('configJson')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                activeScriptTab === 'configJson'
                  ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-sky-300 shadow-xs'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
              }`}
            >
              stage0-config + manifest.json
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => handleCopy(activeScriptTab, displayedCode)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border border-slate-300 dark:border-slate-700 rounded-md text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
            >
              {copiedKey === activeScriptTab ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-500" />
                  Copied
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  Copy Artifact
                </>
              )}
            </button>
            <button
              type="button"
              onClick={() =>
                handleDownloadFile(
                  activeScriptTab === 'probe'
                    ? 'stage0-workstation-probe.mjs'
                    : activeScriptTab === 'canary'
                      ? 'stage0-multi-identity-canary.mjs'
                      : 'stage0-config-bundle.json',
                  displayedCode
                )
              }
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border border-slate-300 dark:border-slate-700 rounded-md text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
            >
              <Download className="w-3.5 h-3.5" />
              Download
            </button>
          </div>
        </div>

        <pre className="p-4 rounded-md bg-slate-950 text-slate-200 text-xs font-mono overflow-x-auto max-h-80 leading-relaxed border border-slate-800">
          <code>{displayedCode}</code>
        </pre>
      </section>
    </div>
  );
};
