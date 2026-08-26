import { Injectable, Logger } from '@nestjs/common';
import { createReadStream } from 'node:fs';
import { chain } from 'stream-chain';
import { parser } from 'stream-json';
import { pick } from 'stream-json/filters/Pick';
import { streamArray } from 'stream-json/streamers/StreamArray';
import { ScanEngineError } from '../../common/errors/scan-engine.error';
import { CriticalVulnerability } from '../interfaces/scan-record.interface';
import { TrivyResult, TrivyVulnerability } from '../interfaces/trivy-report.interface';

interface StreamArrayItem {
  key: number;
  value: unknown;
}

export interface CriticalVulnerabilityExtractionResult {
  vulnerabilities: CriticalVulnerability[];
  /** True count of CRITICAL findings seen, even if the list above was capped. */
  totalCount: number;
  /** True if `totalCount` exceeded MAX_RETAINED_VULNERABILITIES and the list was capped. */
  truncated: boolean;
}

/**
 * Extracts CRITICAL-severity vulnerabilities from a (potentially 500MB+)
 * Trivy JSON report WITHOUT ever loading the file or the full `Results`
 * array into memory.
 *
 * How it stays memory-safe:
 *  - `fs.createReadStream` reads the file in small chunks, never as a whole.
 *  - `stream-json`'s `parser()` tokenizes those chunks incrementally.
 *  - `pick({ filter: 'Results' })` narrows the token stream to only the
 *    `Results` array, discarding everything else (e.g. Trivy metadata) as
 *    it streams past, without buffering it.
 *  - `streamArray()` re-assembles ONE array element at a time (i.e. one
 *    `Results[i]` object - one scan target's findings) and emits a `data`
 *    event per element, then discards it before the next one is built.
 *    The full `Results` array itself is never materialized.
 *  - We keep only vulnerabilities with Severity === 'CRITICAL', and even
 *    that accumulator is capped (see MAX_RETAINED_VULNERABILITIES below) so
 *    a pathological report can't turn "keep only the critical ones" into
 *    its own unbounded-memory problem.
 *
 * Backpressure is handled by stream-chain/stream-json internally: the
 * source read stream is paused while downstream processing catches up, so
 * the whole pipeline stays bounded by chunk size, not file size. This is
 * what makes it safe to run under `--max-old-space-size=150` even against
 * a report far bigger than that heap limit (verified - see
 * scripts/oom-check.js and README.md "OOM self-test").
 *
 * Trade-offs worth calling out:
 *  1. A single `Results[i]` element (one target's full `Vulnerabilities`
 *     array) IS assembled in memory before we scan it. For Trivy reports
 *     this is fine in practice - the 500MB+ scenario comes from having very
 *     many targets/layers, not one target with millions of vulnerabilities.
 *     If that assumption ever breaks, the same `pick`+`stream` technique
 *     can be nested one level deeper (stream `Results[i].Vulnerabilities`
 *     itself) at the cost of a slightly more complex pipeline.
 *  2. The list of CRITICAL vulnerabilities returned to the API is capped at
 *     MAX_RETAINED_VULNERABILITIES. In real-world Trivy output CRITICAL
 *     findings are a small minority - this cap exists purely as a defensive
 *     bound against an adversarial/unexpected report where that assumption
 *     doesn't hold, not because it's expected to be hit. `totalCount` still
 *     reflects the true number found, and `truncated` tells the caller the
 *     list was capped, so nothing is silently dropped without a trace.
 */
const MAX_RETAINED_VULNERABILITIES = 2000;

@Injectable()
export class TrivyStreamParserService {
  private readonly logger = new Logger(TrivyStreamParserService.name);

  async extractCriticalVulnerabilities(
    filePath: string,
  ): Promise<CriticalVulnerabilityExtractionResult> {
    const vulnerabilities: CriticalVulnerability[] = [];
    let totalCount = 0;
    let targetsProcessed = 0;

    const picked = pick({ filter: 'Results' });

    const pipeline = chain([createReadStream(filePath), parser(), picked, streamArray()]);

    // `pick` emits nothing at all when the report has no `Results` key, which
    // after `streamArray()` is indistinguishable from `Results: []` - both
    // produce zero elements. Only the token stream separates them: an empty
    // array still emits startArray/endArray, a missing key emits nothing.
    //
    // Observed with a self-removing listener alongside the pipe rather than a
    // passthrough Transform in the chain: a Transform sees every token in the
    // Results subtree, which measurably doubled parse time on the 500MB+
    // fixture. `once` costs one extra emit, then detaches. It only observes -
    // the pipe still drives flow, so backpressure is unaffected.
    let sawResultsKey = false;
    picked.once('data', () => {
      sawResultsKey = true;
    });

    try {
      await new Promise<void>((resolve, reject) => {
        pipeline.on('data', (item: StreamArrayItem) => {
          targetsProcessed += 1;
          const result = item.value as TrivyResult;
          // Array.isArray rather than `?.length`: a non-array object
          // carrying a `length` property passes a truthiness check and then
          // throws on `for...of`. That throw would happen inside this
          // 'data' listener, escaping the surrounding promise's reject and
          // surfacing as an uncaught exception instead of a PARSE_FAILED.
          if (!Array.isArray(result?.Vulnerabilities) || result.Vulnerabilities.length === 0) {
            return;
          }
          for (const vuln of result.Vulnerabilities) {
            if (vuln.Severity !== 'CRITICAL') {
              continue;
            }
            totalCount += 1;
            if (vulnerabilities.length < MAX_RETAINED_VULNERABILITIES) {
              vulnerabilities.push(toCriticalVulnerability(result.Target, vuln));
            }
          }
        });

        pipeline.on('error', (err: Error) => reject(err));
        pipeline.on('end', () => resolve());
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new ScanEngineError(
        `Failed to stream-parse trivy report at "${filePath}": ${message}`,
        'PARSE_FAILED',
        err,
      );
    }

    // Deliberately outside the try above: this isn't a stream failure to be
    // wrapped, it's a well-formed JSON file that isn't a Trivy report. Left
    // unchecked it would resolve as "0 CRITICAL, FINISHED" - a clean bill of
    // health for a repository nobody actually scanned.
    if (!sawResultsKey) {
      throw new ScanEngineError(
        `Trivy report at "${filePath}" has no "Results" key - not a trivy fs report`,
        'PARSE_FAILED',
      );
    }

    const truncated = totalCount > vulnerabilities.length;
    this.logger.log(
      `Parsed ${targetsProcessed} scan target(s) from ${filePath}, found ${totalCount} CRITICAL vulnerabilit${
        totalCount === 1 ? 'y' : 'ies'
      }${truncated ? ` (retained first ${vulnerabilities.length}, truncated)` : ''}`,
    );

    return { vulnerabilities, totalCount, truncated };
  }
}

function toCriticalVulnerability(
  target: string,
  vuln: TrivyVulnerability,
): CriticalVulnerability {
  return {
    id: `${target}:${vuln.PkgName}:${vuln.VulnerabilityID}`,
    vulnerabilityId: vuln.VulnerabilityID,
    pkgName: vuln.PkgName,
    installedVersion: vuln.InstalledVersion,
    fixedVersion: vuln.FixedVersion,
    severity: 'CRITICAL',
    title: vuln.Title,
    target,
  };
}
