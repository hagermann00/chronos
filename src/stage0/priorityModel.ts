import type {
  AdapterPriorityScore,
  FormatInventoryRecord,
  VendorEcosystemId,
  WorkflowImportanceTier,
} from './types.ts';

interface EcosystemStaticMeta {
  displayName: string;
  baseAccessibilityScore: number; // 0-20 before mixed-container penalty
  baseImplementationScore: number; // 0-20 before existing-harness bonus
  accessibilityNotes: string;
}

export const ECOSYSTEM_METADATA: Record<VendorEcosystemId, EcosystemStaticMeta> = {
  antigravity: {
    displayName: 'Antigravity Conversations & Subagent Trees',
    baseAccessibilityScore: 17,
    baseImplementationScore: 13,
    accessibilityNotes: 'Structured session/subagent logs with parent-child lineage and artifact pointers.',
  },
  gemini_cli: {
    displayName: 'Gemini CLI Sessions',
    baseAccessibilityScore: 18,
    baseImplementationScore: 16,
    accessibilityNotes: 'Local JSON/JSONL session records with explicit turn roles and tool outputs.',
  },
  codex_cli: {
    displayName: 'Codex CLI & Agent Sessions',
    baseAccessibilityScore: 18,
    baseImplementationScore: 16,
    accessibilityNotes: 'Append-only JSONL command/turn logs with per-event timestamps.',
  },
  claude_code: {
    displayName: 'Claude Code CLI Sessions',
    baseAccessibilityScore: 18,
    baseImplementationScore: 16,
    accessibilityNotes: 'Line-delimited JSONL transcripts with parentUuid chains and tool results.',
  },
  gemini_web: {
    displayName: 'Gemini Web Conversations (Takeout / Export)',
    baseAccessibilityScore: 14,
    baseImplementationScore: 13,
    accessibilityNotes: 'Export envelopes vary across Takeout vs activity archives; requires structural check.',
  },
  chatgpt_openai: {
    displayName: 'ChatGPT / OpenAI Exports',
    baseAccessibilityScore: 16,
    baseImplementationScore: 14,
    accessibilityNotes: 'Monolithic conversations.json mapping DAG; high mixed-container quarantine risk.',
  },
  claude_web: {
    displayName: 'Claude Web Conversation Exports',
    baseAccessibilityScore: 16,
    baseImplementationScore: 15,
    accessibilityNotes: 'Monolithic JSON export with typed message blocks and artifact tags.',
  },
  manus: {
    displayName: 'Manus Task Histories',
    baseAccessibilityScore: 12,
    baseImplementationScore: 11,
    accessibilityNotes: 'Multi-step agent task envelopes; format revisions require sample validation.',
  },
  grok: {
    displayName: 'Grok Export Histories',
    baseAccessibilityScore: 13,
    baseImplementationScore: 13,
    accessibilityNotes: 'Account archive JSON envelopes; timestamp precision varies by export version.',
  },
  deepseek: {
    displayName: 'DeepSeek Conversation Histories',
    baseAccessibilityScore: 15,
    baseImplementationScore: 15,
    accessibilityNotes: 'JSON export separating reasoning_content from final response content.',
  },
  unknown_structured: {
    displayName: 'Unclassified Structured JSON / JSONL / SQLite',
    baseAccessibilityScore: 8,
    baseImplementationScore: 8,
    accessibilityNotes: 'Requires manual schema review after Stage 0 signature inspection.',
  },
};

const WORKFLOW_POINTS: Record<WorkflowImportanceTier, number> = {
  CRITICAL_ACTIVE_WORK: 35,
  HIGH_REFERENCE: 22,
  ARCHIVAL_LOW: 8,
};

/**
 * Ranks UNVERIFIED candidate adapters using four explicit empirical factors:
 * 1. Observed Usable Data Volume & Container Count (0–25 pts, log-scaled so file count alone never dominates)
 * 2. Owner Workflow Importance (0–35 pts)
 * 3. Format Accessibility, Timestamp Granularity & Mixed-Archive Cleanliness (0–20 pts)
 * 4. Implementation Cost & Existing Universal Harness Reuse (0–20 pts)
 */
export function computeFourFactorAdapterPriorities(
  inventory: FormatInventoryRecord[],
  workflowWeights: Record<VendorEcosystemId, WorkflowImportanceTier>
): AdapterPriorityScore[] {
  const maxBytes = Math.max(
    1,
    ...inventory.map((r) => Math.max(0, r.nonQuarantinedBytes))
  );
  const maxContainers = Math.max(
    1,
    ...inventory.map((r) => Math.max(0, r.estimatedContainerCount))
  );

  const scored: AdapterPriorityScore[] = inventory.map((rec) => {
    const meta = ECOSYSTEM_METADATA[rec.ecosystem] ?? ECOSYSTEM_METADATA.unknown_structured;
    const tier: WorkflowImportanceTier =
      workflowWeights[rec.ecosystem] ?? 'HIGH_REFERENCE';

    // Factor 1: Observed Usable Volume (bytes weighted 75%, container count 25%, zero if 0 bytes)
    let volumeScore = 0;
    if (rec.nonQuarantinedBytes > 0) {
      const byteNorm =
        Math.log10(rec.nonQuarantinedBytes + 1) / Math.log10(maxBytes + 1);
      const containerNorm =
        Math.log10(rec.estimatedContainerCount + 1) /
        Math.log10(maxContainers + 1);
      volumeScore = Math.round((byteNorm * 0.75 + containerNorm * 0.25) * 25);
    }

    // Factor 2: Owner Workflow Importance (gated down if zero observed non-quarantined data)
    const rawWorkflow = WORKFLOW_POINTS[tier];
    const workflowScore =
      rec.nonQuarantinedBytes > 0 ? rawWorkflow : Math.round(rawWorkflow * 0.25);

    // Factor 3: Accessibility, Explicit Event Timestamps & Mixed-Archive Penalty
    let accessibilityScore = meta.baseAccessibilityScore;
    if (rec.hasExplicitEventTimestamps === true) {
      accessibilityScore = Math.min(20, accessibilityScore + 2);
    } else if (rec.hasExplicitEventTimestamps === false) {
      accessibilityScore = Math.max(2, accessibilityScore - 4);
    }
    if (rec.mixedArchiveRiskCount > 0) {
      accessibilityScore = Math.max(2, accessibilityScore - 5);
    }

    // Factor 4: Implementation Cost & Existing Universal Harness Reuse Bonus
    let implementationReuseScore = meta.baseImplementationScore;
    if (rec.existingHarnessReuseDetected) {
      implementationReuseScore = Math.min(20, implementationReuseScore + 4);
    }

    const compositeScore =
      volumeScore + workflowScore + accessibilityScore + implementationReuseScore;

    const rationaleParts: string[] = [];
    if (rec.nonQuarantinedBytes === 0) {
      rationaleParts.push('Zero non-quarantined bytes observed in allowlisted roots');
    } else {
      rationaleParts.push(
        `${formatBytesCompact(rec.nonQuarantinedBytes)} across ${rec.estimatedContainerCount} container(s)`
      );
    }
    rationaleParts.push(`Workflow=${tier}`);
    if (rec.existingHarnessReuseDetected) {
      rationaleParts.push('Existing Universal Harness coverage detected (+reuse)');
    }
    if (rec.mixedArchiveRiskCount > 0) {
      rationaleParts.push(
        `${rec.mixedArchiveRiskCount} mixed/quarantined container(s) require pre-ingest filter`
      );
    }

    return {
      ecosystem: rec.ecosystem,
      displayName: meta.displayName,
      verificationStatus: 'UNVERIFIED',
      usableBytes: rec.nonQuarantinedBytes,
      usableFileCount: rec.nonQuarantinedFileCount,
      workflowTier: tier,
      volumeScore,
      workflowScore,
      accessibilityScore,
      implementationReuseScore,
      compositeScore,
      mixedRiskFlag: rec.mixedArchiveRiskCount > 0,
      rationale: rationaleParts.join(' · '),
    };
  });

  return scored.sort((a, b) => b.compositeScore - a.compositeScore);
}

function formatBytesCompact(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}
