import fs from 'node:fs';
import { Stage0FailClosedError } from './pathSecurity.ts';
import { executeStage0Discovery } from './traversalEngine.ts';
import type { MultiIdentityCanaryResult, Stage0Config } from './types.ts';

function getArgValue(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  if (idx === -1 || idx + 1 >= args.length) return undefined;
  return args[idx + 1];
}

function readRegularFileNoFollowUtf8(filePath: string, errorCode: string): string {
  const fsConsts = fs.constants as Record<string, number>;
  const flags =
    fs.constants.O_RDONLY |
    (fs.constants.O_NOFOLLOW ?? 0) |
    (fs.constants.O_NONBLOCK ?? 0) |
    (fsConsts.O_CLOEXEC ?? 0);

  let fd: number | null = null;
  try {
    fd = fs.openSync(filePath, flags);
    const fst = fs.fstatSync(fd);
    if (!fst.isFile()) {
      throw new Stage0FailClosedError(
        errorCode === 'FAIL_CLOSED_86_INIT' ? 'FAIL_CLOSED_86_INIT' : 'FAIL_CLOSED_CONFIG',
        'INPUT_FILE_NOT_REGULAR',
        'Refusing to read non-regular input file.'
      );
    }
    return fs.readFileSync(fd, 'utf8');
  } catch (err) {
    if (err instanceof Stage0FailClosedError) throw err;
    throw new Stage0FailClosedError(
      errorCode === 'FAIL_CLOSED_86_INIT' ? 'FAIL_CLOSED_86_INIT' : 'FAIL_CLOSED_CONFIG',
      'INPUT_FILE_READ_FAILED',
      `Unable to safely open regular input file (symlinks/missing paths fail closed).`
    );
  } finally {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {
        // ignore
      }
    }
  }
}

function main(): void {
  const args = process.argv.slice(2);
  const configPath = getArgValue(args, '--config');
  if (!configPath) {
    console.error(
      'FAIL_CLOSED_CONFIG: Usage: node stage0-workstation-probe.mjs --config <stage0-config.json> --expected-manifest-sha256 <64-hex> [--canary-report <canary-results.json>]'
    );
    process.exit(2);
  }

  try {
    const configRaw = readRegularFileNoFollowUtf8(configPath, 'FAIL_CLOSED_CONFIG');
    let config: Stage0Config;
    try {
      config = JSON.parse(configRaw) as Stage0Config;
    } catch {
      throw new Stage0FailClosedError(
        'FAIL_CLOSED_CONFIG',
        'CONFIG_JSON_PARSE_ERROR',
        'Stage 0 config file is not valid JSON.'
      );
    }

    if (!config || typeof config.external86ManifestPath !== 'string' || !config.external86ManifestPath.trim()) {
      throw new Stage0FailClosedError(
        'FAIL_CLOSED_86_INIT',
        'MISSING_EXTERNAL_86_MANIFEST_PATH',
        'Stage 0 config must specify external86ManifestPath.'
      );
    }

    let cliExpectedSha256 = getArgValue(args, '--expected-manifest-sha256');
    const shaFile = getArgValue(args, '--manifest-sha256-file');
    if (shaFile) {
      const digestFileText = readRegularFileNoFollowUtf8(shaFile, 'FAIL_CLOSED_86_INIT').trim();
      // Support standard `sha256sum` output ("<hex>  <filename>") or raw 64-hex line
      const firstToken = digestFileText.split(/\s+/)[0] ?? '';
      if (cliExpectedSha256 && cliExpectedSha256.trim().toLowerCase() !== firstToken.toLowerCase()) {
        throw new Stage0FailClosedError(
          'FAIL_CLOSED_86_INIT',
          'CONFLICTING_EXPECTED_MANIFEST_SHA256',
          '--expected-manifest-sha256 and --manifest-sha256-file disagree; failing closed.'
        );
      }
      cliExpectedSha256 = firstToken;
    }

    const manifestRawJson = readRegularFileNoFollowUtf8(
      config.external86ManifestPath,
      'FAIL_CLOSED_86_INIT'
    );

    let canaryResults: MultiIdentityCanaryResult[] | undefined;
    const canaryReportPath = getArgValue(args, '--canary-report');
    if (canaryReportPath) {
      const canaryRaw = readRegularFileNoFollowUtf8(canaryReportPath, 'FAIL_CLOSED_CONFIG');
      const parsedCanary = JSON.parse(canaryRaw) as
        | MultiIdentityCanaryResult[]
        | { results?: MultiIdentityCanaryResult[] };
      canaryResults = Array.isArray(parsedCanary)
        ? parsedCanary
        : Array.isArray(parsedCanary?.results)
          ? parsedCanary.results
          : undefined;
    }

    const { report, writtenReportPath } = executeStage0Discovery({
      config,
      manifestRawJson,
      expectedManifestSha256: cliExpectedSha256,
      evidenceOrigin: 'WORKSTATION_IMPORTED_REPORT',
      canaryResults,
      writeReportFileToZoneB: true,
    });

    console.log(
      JSON.stringify(
        {
          status: 'STAGE_0_COMPLETE_SANITIZED',
          writtenReportPath,
          manifestId: report.securityAudit.manifestId,
          manifestSha256: report.securityAudit.manifestSha256,
          manifestIntegrityVerified: report.securityAudit.manifestIntegrityVerified,
          allowlistRootCount: report.securityAudit.allowlistRootCount,
        },
        null,
        2
      )
    );
  } catch (err) {
    if (err instanceof Stage0FailClosedError) {
      console.error(`${err.code} [${err.detailCode}]: ${err.message}`);
      const exitCode =
        err.code === 'FAIL_CLOSED_CONFIG'
          ? 2
          : err.code === 'FAIL_CLOSED_86_INIT'
            ? 3
            : err.code === 'FAIL_CLOSED_ZONE_OVERLAP'
              ? 4
              : err.code === 'FAIL_CLOSED_SANITIZATION_BREACH'
                ? 5
                : 6;
      process.exit(exitCode);
    }
    console.error(
      `FAIL_CLOSED_UNCERTAIN: ${err instanceof Error ? err.message : 'Unexpected Stage 0 failure'}`
    );
    process.exit(1);
  }
}

main();
