import type {
  External86Manifest,
  SanitizedStage0Report,
  Stage0Config,
  VendorEcosystemId,
  WorkflowImportanceTier,
} from './types.ts';

export const DEFAULT_WORKFLOW_WEIGHTS: Record<VendorEcosystemId, WorkflowImportanceTier> = {
  antigravity: 'CRITICAL_ACTIVE_WORK',
  gemini_cli: 'CRITICAL_ACTIVE_WORK',
  codex_cli: 'CRITICAL_ACTIVE_WORK',
  claude_code: 'CRITICAL_ACTIVE_WORK',
  gemini_web: 'HIGH_REFERENCE',
  chatgpt_openai: 'HIGH_REFERENCE',
  claude_web: 'HIGH_REFERENCE',
  manus: 'ARCHIVAL_LOW',
  grok: 'ARCHIVAL_LOW',
  deepseek: 'ARCHIVAL_LOW',
  unknown_structured: 'ARCHIVAL_LOW',
};

export const DEFAULT_NTFS_STAGE0_CONFIG: Stage0Config = {
  configVersion: '1.0.0',
  hostOsMode: 'WINDOWS_NTFS',
  scanRootsAllowlist: [
    {
      alias: 'ROOT_01',
      absolutePath: 'D:\\AI_Archives\\Authorized_Sessions',
      expectedFsMode: 'WINDOWS_NTFS',
      ntfsCaseSensitiveDir: false,
    },
    {
      alias: 'ROOT_02',
      absolutePath: 'D:\\Engineering\\Agent_Logs',
      expectedFsMode: 'WINDOWS_NTFS',
      ntfsCaseSensitiveDir: false,
    },
  ],
  external86ManifestPath: 'D:\\Governance\\external-86-manifest.json',
  zoneBOutputDir: 'D:\\Stage0_Authorized_Reports\\run_01',
  universalHarnessProbePaths: ['D:\\Engineering\\Universal_Harness'],
  existingSqliteLedgerPaths: ['D:\\Engineering\\Ledgers\\closeout_ledger.sqlite'],
  workflowWeights: { ...DEFAULT_WORKFLOW_WEIGHTS },
};

export const DEFAULT_POSIX_STAGE0_CONFIG: Stage0Config = {
  configVersion: '1.0.0',
  hostOsMode: 'POSIX',
  scanRootsAllowlist: [
    {
      alias: 'ROOT_01',
      absolutePath: '/srv/ai-archives/authorized-sessions',
      expectedFsMode: 'POSIX',
    },
  ],
  external86ManifestPath: '/srv/governance/external-86-manifest.json',
  zoneBOutputDir: '/tmp/chronos-stage0-output',
  universalHarnessProbePaths: ['/srv/engineering/universal-harness'],
  existingSqliteLedgerPaths: ['/srv/engineering/ledgers/closeout.sqlite'],
  workflowWeights: { ...DEFAULT_WORKFLOW_WEIGHTS },
};

export const DEFAULT_EXTERNAL_86_MANIFEST: External86Manifest = {
  schemaVersion: '1.0.0',
  manifestId: 'EXT_86_MANIFEST_2026_11',
  ownerApprovedAtIso: '2026-11-22T07:00:00.000Z',
  allowEmptyRuleset: false,
  rules: [
    {
      ruleId: 'R86_CLIENT_VAULT_01',
      kind: 'PATH_PREFIX',
      targetValue: 'D:\\AI_Archives\\Authorized_Sessions\\Excluded_Vault_86',
      reasonCode: 'OWNER_REVOKED_SCOPE',
    },
    {
      ruleId: 'R86_ARCHIVE_MEMBER_02',
      kind: 'ARCHIVE_ENTRY_NAME',
      targetValue: 'revoked_project_thread',
      reasonCode: 'MIXED_ZIP_EXCLUSION',
    },
    {
      ruleId: 'R86_CONV_UUID_03',
      kind: 'REVOKED_CONVERSATION_ID',
      targetValue: 'conv_revoked_98a76b54',
      reasonCode: 'SINGLE_CONVERSATION_86',
    },
  ],
};

/**
 * Explicitly badged SYNTHETIC_FIXTURE_PREVIEW payload for exercising the Report Validator &
 * 4-Factor Priority Matrix UI without pretending the Dell workstation has been inspected.
 */
export const SYNTHETIC_VALID_STAGE0_FIXTURE: SanitizedStage0Report = {
  schemaVersion: '1.0.0',
  stage: 'STAGE_0_READ_ONLY_DISCOVERY',
  evidenceOrigin: 'SYNTHETIC_FIXTURE_PREVIEW',
  generatedAtIso: '2026-11-22T07:30:00.000Z',
  hostProfile: {
    osPlatform: 'win32_synthetic_fixture',
    osRelease: '10.0.26100_synthetic',
    cpuCores: 16,
    totalMemBytes: 68719476736,
    freeMemBytes: 42949672960,
    gpuSummary: {
      detectionState: 'DETECTED',
      devices: [{ modelCode: 'SYNTHETIC_FIXTURE_GPU_EXAMPLE', vramTotalMb: 24576, vramFreeMb: 21400 }],
    },
    llamaCppStatus: {
      serverBinaryPresent: true,
      cliBinaryPresent: true,
      versionTag: 'SYNTHETIC_B4100',
      ggufHeaderCount: 4,
    },
    gcloudCliPresent: true,
    rootFilesystems: [
      { rootAlias: 'ROOT_01', fsMode: 'WINDOWS_NTFS' },
      { rootAlias: 'ROOT_02', fsMode: 'WINDOWS_NTFS' },
    ],
  },
  securityAudit: {
    allowlistRootCount: 2,
    manifestId: 'EXT_86_MANIFEST_SYNTHETIC',
    manifestSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    manifestIntegrityVerified: true,
    pruned86ByRuleId: {
      R86_CLIENT_VAULT_01: 14,
      R86_ARCHIVE_MEMBER_02: 2,
    },
    reparseOrSymlinkSkippedCount: 3,
    mountCrossingSkippedCount: 0,
    hardlinkAliasBlockedCount: 1,
    cloudPlaceholderSkippedCount: 5,
    mixedContainerQuarantinedCount: 2,
    potentialMixedUnscannedCount: 1,
    failClosedUncertainCount: 0,
    zoneAWriteViolations: 0,
    multiIdentityCanaryResults: [
      {
        identityLabel: 'Isolated Agent Local Account vs Explicit NTFS DENY Vault',
        principalKind: 'ISOLATED_AGENT_UID',
        probeOperationsTested: ['READ_FILE', 'LIST_DIR', 'SEARCH_TEXT'],
        outcome: 'PASS_OS_ENFORCED_DENIED',
        osErrorCode: 'ERROR_ACCESS_DENIED_5',
        remediationNote: 'Synthetic example: separate local SID blocked by NTFS DENY ACE.',
      },
      {
        identityLabel: 'Unisolated Same-SID CLI Process vs User Folder',
        principalKind: 'CLI_AGENT_SAME_UID',
        probeOperationsTested: ['READ_FILE', 'LIST_DIR', 'SEARCH_TEXT'],
        outcome: 'FAIL_EXPOSED_TO_IDENTITY',
        osErrorCode: 'EXIT_0_SAME_SID_READABLE',
        remediationNote: 'Synthetic example: move 86 vault to unmounted VHDX or dedicated vault SID.',
      },
    ],
  },
  reuseInventory: {
    universalHarnessDetected: true,
    universalHarnessEntrypointsCount: 3,
    sqliteLedgersInspected: [
      {
        ledgerAlias: 'LEDGER_01',
        tableName: 'harness_runs',
        columns: [
          { name: 'run_id', declaredType: 'TEXT' },
          { name: 'agent_name', declaredType: 'TEXT' },
          { name: 'started_at', declaredType: 'TEXT' },
          { name: 'status', declaredType: 'TEXT' },
        ],
        indexNames: ['idx_harness_runs_started_at'],
        approximateRowCount: null,
        openedImmutableReadOnly: true,
      },
      {
        ledgerAlias: 'LEDGER_01',
        tableName: 'chat_closeouts',
        columns: [
          { name: 'closeout_id', declaredType: 'TEXT' },
          { name: 'session_ref', declaredType: 'TEXT' },
          { name: 'recorded_at', declaredType: 'TEXT' },
        ],
        indexNames: ['idx_chat_closeouts_session_ref'],
        approximateRowCount: null,
        openedImmutableReadOnly: true,
      },
    ],
    reuseAssessmentCode: 'CANDIDATE_HARNESS_EXTENSION',
  },
  formatInventory: [
    {
      ecosystem: 'antigravity',
      verificationStatus: 'UNVERIFIED',
      nonQuarantinedFileCount: 142,
      nonQuarantinedBytes: 48200000,
      estimatedContainerCount: 64,
      hasExplicitEventTimestamps: true,
      mixedArchiveRiskCount: 0,
      existingHarnessReuseDetected: true,
    },
    {
      ecosystem: 'gemini_cli',
      verificationStatus: 'UNVERIFIED',
      nonQuarantinedFileCount: 96,
      nonQuarantinedBytes: 31500000,
      estimatedContainerCount: 96,
      hasExplicitEventTimestamps: true,
      mixedArchiveRiskCount: 0,
      existingHarnessReuseDetected: true,
    },
    {
      ecosystem: 'codex_cli',
      verificationStatus: 'UNVERIFIED',
      nonQuarantinedFileCount: 84,
      nonQuarantinedBytes: 24800000,
      estimatedContainerCount: 84,
      hasExplicitEventTimestamps: true,
      mixedArchiveRiskCount: 0,
      existingHarnessReuseDetected: true,
    },
    {
      ecosystem: 'claude_code',
      verificationStatus: 'UNVERIFIED',
      nonQuarantinedFileCount: 58,
      nonQuarantinedBytes: 19400000,
      estimatedContainerCount: 58,
      hasExplicitEventTimestamps: true,
      mixedArchiveRiskCount: 0,
      existingHarnessReuseDetected: false,
    },
    {
      ecosystem: 'chatgpt_openai',
      verificationStatus: 'UNVERIFIED',
      nonQuarantinedFileCount: 2,
      nonQuarantinedBytes: 92000000,
      estimatedContainerCount: 2,
      hasExplicitEventTimestamps: true,
      mixedArchiveRiskCount: 1,
      existingHarnessReuseDetected: false,
    },
    {
      ecosystem: 'claude_web',
      verificationStatus: 'UNVERIFIED',
      nonQuarantinedFileCount: 1,
      nonQuarantinedBytes: 18400000,
      estimatedContainerCount: 1,
      hasExplicitEventTimestamps: true,
      mixedArchiveRiskCount: 0,
      existingHarnessReuseDetected: false,
    },
    {
      ecosystem: 'gemini_web',
      verificationStatus: 'UNVERIFIED',
      nonQuarantinedFileCount: 12,
      nonQuarantinedBytes: 6400000,
      estimatedContainerCount: 12,
      hasExplicitEventTimestamps: 'UNKNOWN',
      mixedArchiveRiskCount: 1,
      existingHarnessReuseDetected: false,
    },
    {
      ecosystem: 'deepseek',
      verificationStatus: 'UNVERIFIED',
      nonQuarantinedFileCount: 3,
      nonQuarantinedBytes: 2100000,
      estimatedContainerCount: 3,
      hasExplicitEventTimestamps: true,
      mixedArchiveRiskCount: 0,
      existingHarnessReuseDetected: false,
    },
    {
      ecosystem: 'manus',
      verificationStatus: 'UNVERIFIED',
      nonQuarantinedFileCount: 0,
      nonQuarantinedBytes: 0,
      estimatedContainerCount: 0,
      hasExplicitEventTimestamps: 'UNKNOWN',
      mixedArchiveRiskCount: 0,
      existingHarnessReuseDetected: false,
    },
    {
      ecosystem: 'grok',
      verificationStatus: 'UNVERIFIED',
      nonQuarantinedFileCount: 0,
      nonQuarantinedBytes: 0,
      estimatedContainerCount: 0,
      hasExplicitEventTimestamps: 'UNKNOWN',
      mixedArchiveRiskCount: 0,
      existingHarnessReuseDetected: false,
    },
    {
      ecosystem: 'unknown_structured',
      verificationStatus: 'UNVERIFIED',
      nonQuarantinedFileCount: 4,
      nonQuarantinedBytes: 540000,
      estimatedContainerCount: 4,
      hasExplicitEventTimestamps: 'UNKNOWN',
      mixedArchiveRiskCount: 0,
      existingHarnessReuseDetected: false,
    },
  ],
};

/**
 * Intentional violation fixture demonstrating Zero-Leak Sanitizer hard rejection.
 */
export const SYNTHETIC_UNSANITIZED_LEAK_SAMPLE = {
  schemaVersion: '1.0.0',
  stage: 'STAGE_0_READ_ONLY_DISCOVERY',
  evidenceOrigin: 'WORKSTATION_IMPORTED_REPORT',
  generatedAtIso: '2026-11-22T07:35:00.000Z',
  hostProfile: {
    osPlatform: 'win32',
    rootFilesystems: [{ rootAlias: 'C:\\Users\\owner\\Desktop\\RawLeak', fsMode: 'WINDOWS_NTFS' }],
  },
  securityAudit: {
    pruned86ByRuleId: {
      'D:\\Secret\\86_Folder': 3,
    },
  },
  formatInventory: [
    {
      ecosystem: 'chatgpt_openai',
      verificationStatus: 'PROVEN', // Illegal premature claim!
      title: 'Private Architecture Brainstorm Session', // Forbidden content key!
      apiKey: 'sk-proj1234567890abcdefghijklmnop', // Secret pattern + forbidden key!
    },
  ],
};
