/**
 * Stage 0 Execution Contract, Security Boundaries, Sanitized Output & Priority Types.
 * Scope: STAGE 0 READ-ONLY ASSESSMENT ONLY. Stage 1+ implementation is NOT authorized.
 */

export type OsPlatformMode = 'WINDOWS_NTFS' | 'POSIX';

export type FailClosedCode =
  | 'FAIL_CLOSED_CONFIG'
  | 'FAIL_CLOSED_86_INIT'
  | 'FAIL_CLOSED_FS'
  | 'FAIL_CLOSED_UNCERTAIN'
  | 'FAIL_CLOSED_ZONE_OVERLAP'
  | 'FAIL_CLOSED_SANITIZATION_BREACH';

export type WorkflowImportanceTier =
  | 'CRITICAL_ACTIVE_WORK'
  | 'HIGH_REFERENCE'
  | 'ARCHIVAL_LOW';

export type VendorEcosystemId =
  | 'antigravity'
  | 'gemini_cli'
  | 'codex_cli'
  | 'claude_code'
  | 'gemini_web'
  | 'chatgpt_openai'
  | 'claude_web'
  | 'manus'
  | 'grok'
  | 'deepseek'
  | 'unknown_structured';

export interface ScanRootEntry {
  alias: string; // e.g., ROOT_01 (opaque identifier used in sanitized output)
  absolutePath: string; // Never echoed into sanitized output
  expectedFsMode: OsPlatformMode;
  ntfsCaseSensitiveDir?: boolean;
}

export type Rule86Kind =
  | 'PATH_PREFIX'
  | 'FILENAME_EXACT'
  | 'GLOB_SEGMENT'
  | 'POSIX_DEV_INO'
  | 'NTFS_FILE_ID_128'
  | 'ARCHIVE_ENTRY_NAME'
  | 'REVOKED_CONVERSATION_ID'
  | 'KNOWN_MIXED_CONTAINER';

export interface Rule86Entry {
  ruleId: string; // Opaque administrative ID (e.g., R86_001) safe to emit in audit counts
  kind: Rule86Kind;
  targetValue: string; // Sensitive pattern/path/ID — NEVER emitted in Stage 0 reports
  reasonCode: string; // Sanitized enum-like code, e.g., OWNER_REVOKED_PROJECT
}

export interface External86Manifest {
  schemaVersion: '1.0.0';
  manifestId: string;
  ownerApprovedAtIso: string;
  allowEmptyRuleset?: boolean;
  rules: Rule86Entry[];
}

export interface Stage0Config {
  configVersion: '1.0.0';
  hostOsMode: OsPlatformMode;
  scanRootsAllowlist: ScanRootEntry[];
  external86ManifestPath: string;
  zoneBOutputDir: string;
  universalHarnessProbePaths?: string[];
  existingSqliteLedgerPaths?: string[];
  workflowWeights: Record<VendorEcosystemId, WorkflowImportanceTier>;
}

export type EntryDisposition =
  | 'CLEARED_STRUCTURAL_SNIFFED'
  | 'CLEARED_SQLITE_DDL_INSPECTED'
  | 'CLEARED_ZIP_TOC_CLEAN'
  | 'PRUNED_86_PRE_OPEN'
  | 'SKIPPED_SYMLINK_OR_REPARSE'
  | 'SKIPPED_MOUNT_BOUNDARY_CROSSING'
  | 'SKIPPED_HARDLINK_86_ALIAS'
  | 'SKIPPED_CLOUD_HYDRATION_PLACEHOLDER'
  | 'QUARANTINED_MIXED_CONTAINER'
  | 'QUARANTINED_POTENTIAL_MIXED_UNSCANNED'
  | 'QUARANTINED_FAIL_CLOSED_UNCERTAIN';

export interface SqliteTableSchemaSummary {
  ledgerAlias: string;
  tableName: string;
  columns: Array<{ name: string; declaredType: string }>;
  indexNames: string[];
  approximateRowCount: number | null;
  openedImmutableReadOnly: boolean;
}

export interface FormatInventoryRecord {
  ecosystem: VendorEcosystemId;
  verificationStatus: 'UNVERIFIED'; // Strictly locked to UNVERIFIED in Stage 0
  nonQuarantinedFileCount: number;
  nonQuarantinedBytes: number;
  estimatedContainerCount: number;
  hasExplicitEventTimestamps: boolean | 'UNKNOWN';
  mixedArchiveRiskCount: number;
  existingHarnessReuseDetected: boolean;
}

export type CanaryIdentityOutcome =
  | 'PASS_OS_ENFORCED_DENIED'
  | 'PASS_UNMOUNTED_NOT_VISIBLE'
  | 'FAIL_EXPOSED_TO_IDENTITY'
  | 'ERROR_UNCERTAIN_PROBE';

export interface MultiIdentityCanaryResult {
  identityLabel: string;
  principalKind: 'INTERACTIVE_OWNER' | 'CLI_AGENT_SAME_UID' | 'ISOLATED_AGENT_UID' | 'SEARCH_SUBPROCESS';
  probeOperationsTested: Array<'READ_FILE' | 'LIST_DIR' | 'SEARCH_TEXT'>;
  outcome: CanaryIdentityOutcome;
  osErrorCode: string;
  remediationNote: string;
}

export interface SanitizedStage0Report {
  schemaVersion: '1.0.0';
  stage: 'STAGE_0_READ_ONLY_DISCOVERY';
  evidenceOrigin:
    | 'UNINSPECTED_NO_REPORT'
    | 'SANDBOX_SCRATCH_VERIFICATION'
    | 'SYNTHETIC_FIXTURE_PREVIEW'
    | 'WORKSTATION_IMPORTED_REPORT';
  generatedAtIso: string;
  hostProfile: {
    osPlatform: string;
    osRelease: string;
    cpuCores: number;
    totalMemBytes: number;
    freeMemBytes: number;
    gpuSummary: {
      detectionState: 'DETECTED' | 'NONE_DETECTED' | 'UNINSPECTED';
      devices: Array<{ modelCode: string; vramTotalMb: number; vramFreeMb: number }>;
    };
    llamaCppStatus: {
      serverBinaryPresent: boolean;
      cliBinaryPresent: boolean;
      versionTag: string;
      ggufHeaderCount: number;
    };
    gcloudCliPresent: boolean;
    rootFilesystems: Array<{ rootAlias: string; fsMode: OsPlatformMode }>;
  };
  securityAudit: {
    allowlistRootCount: number;
    manifestId: string;
    manifestSha256: string;
    pruned86ByRuleId: Record<string, number>;
    reparseOrSymlinkSkippedCount: number;
    mountCrossingSkippedCount: number;
    hardlinkAliasBlockedCount: number;
    cloudPlaceholderSkippedCount: number;
    mixedContainerQuarantinedCount: number;
    potentialMixedUnscannedCount: number;
    failClosedUncertainCount: number;
    zoneAWriteViolations: number;
    multiIdentityCanaryResults: MultiIdentityCanaryResult[];
  };
  reuseInventory: {
    universalHarnessDetected: boolean;
    universalHarnessEntrypointsCount: number;
    sqliteLedgersInspected: SqliteTableSchemaSummary[];
    reuseAssessmentCode:
      | 'PENDING_WORKSTATION_EVIDENCE'
      | 'CANDIDATE_HARNESS_EXTENSION'
      | 'CANDIDATE_MODULAR_COMPANION'
      | 'CANDIDATE_MINIMAL_CORE';
  };
  formatInventory: FormatInventoryRecord[];
}

export interface AdapterPriorityScore {
  ecosystem: VendorEcosystemId;
  displayName: string;
  verificationStatus: 'UNVERIFIED';
  usableBytes: number;
  usableFileCount: number;
  workflowTier: WorkflowImportanceTier;
  volumeScore: number; // 0-25
  workflowScore: number; // 0-35
  accessibilityScore: number; // 0-20
  implementationReuseScore: number; // 0-20
  compositeScore: number; // 0-100
  mixedRiskFlag: boolean;
  rationale: string;
}
