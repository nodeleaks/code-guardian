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

/**
 * Where extracted findings go. Implemented by the caller so this service stays
 * free of any storage dependency - ScanProcessor passes one backed by Redis,
 * scripts/oom-check.ts passes one that only counts.
 */
export interface CriticalVulnerabilitySink {
  write(batch: CriticalVulnerability[]): Promise<void>;
}

export interface CriticalVulnerabilityExtractionResult {
  /** Number of CRITICAL findings handed to the sink. */
  totalCount: number;
}

/**
 * Extracts CRITICAL-severity vulnerabilities from a (potentially 500MB+)
 * Trivy JSON report WITHOUT ever loading the file, the full `Results` array,
 * or the full set of findings into memory.
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
 *  - Matching findings accumulate only up to FLUSH_BATCH_SIZE before being
 *    handed to the sink and dropped, so the output side is bounded too - by
 *    the batch size, not by how many findings the report contains.
 *
 * Backpressure is handled on both sides. Upstream, stream-chain/stream-json
 * pause the source read stream while downstream processing catches up.
 * Downstream, this service pauses the pipeline itself while a batch is being
 * written (see the flush logic below), because the sink is async and the
 * `data` handler is not. This is what makes it safe to run under
 * `--max-old-space-size=150` even against a report far bigger than that heap
 * limit (verified - see scripts/oom-check.js and README.md "OOM self-test").
 *
 * Trade-off worth calling out: a single `Results[i]` element (one target's
 * full `Vulnerabilities` array) IS assembled in memory before we scan it. For
 * Trivy reports this is fine in practice - the 500MB+ scenario comes from
 * having very many targets/layers, not one target with millions of
 * vulnerabilities. If that assumption ever breaks, the same `pick`+`stream`
 * technique can be nested one level deeper (stream `Results[i].Vulnerabilities`
 * itself) at the cost of a slightly more complex pipeline.
 */
const FLUSH_BATCH_SIZE = 500;

@Injectable()
export class TrivyStreamParserService {
  private readonly logger = new Logger(TrivyStreamParserService.name);

  async extractCriticalVulnerabilities(
    filePath: string,
    sink: CriticalVulnerabilitySink,
  ): Promise<CriticalVulnerabilityExtractionResult> {
    let buffer: CriticalVulnerability[] = [];
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
        // Serialises sink writes. Without this, two flushes triggered close
        // together would race and could interleave batches, scrambling the
        // stored order that pagination depends on.
        let pending: Promise<void> = Promise.resolve();
        let failed = false;

        const fail = (err: unknown) => {
          failed = true;
          // Normalised to an Error so the rejection reason has a stable
          // shape; the catch below re-wraps it as a ScanEngineError anyway.
          reject(err instanceof Error ? err : new Error(String(err)));
        };

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
            // Trivy is already told to filter to CRITICAL (see
            // TrivyRunnerService), so in practice nothing is skipped here.
            // Kept as validation at the boundary with an external process:
            // nothing proves the installed binary honours --severity.
            if (vuln.Severity !== 'CRITICAL') {
              continue;
            }
            totalCount += 1;
            buffer.push(toCriticalVulnerability(result.Target, vuln, totalCount));
          }

          if (buffer.length < FLUSH_BATCH_SIZE || failed) {
            return;
          }

          // The sink is async but this handler is not, so awaiting here would
          // not stop the stream and the buffer would keep growing. Pause
          // synchronously, hand the batch off, resume once it is written.
          const batch = buffer;
          buffer = [];
          pipeline.pause();
          pending = pending.then(() => sink.write(batch)).then(
            () => {
              if (!failed) {
                pipeline.resume();
              }
            },
            fail,
          );
        });

        pipeline.on('error', fail);
        pipeline.on('end', () => {
          // Drain whatever the last flush left behind before resolving,
          // otherwise the tail of the report is silently dropped.
          pending
            .then(() => sink.write(buffer))
            .then(() => {
              buffer = [];
              resolve();
            }, fail);
        });
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

    this.logger.log(
      `Parsed ${targetsProcessed} scan target(s) from ${filePath}, stored ${totalCount} CRITICAL vulnerabilit${
        totalCount === 1 ? 'y' : 'ies'
      }`,
    );

    return { totalCount };
  }
}

function toCriticalVulnerability(
  target: string,
  vuln: TrivyVulnerability,
  index: number,
): CriticalVulnerability {
  return {
    // `target:pkg:CVE` alone is not always unique - Trivy can report the same
    // package/CVE/target combination more than once (e.g. reached via more
    // than one path in the dependency tree), which broke the `ID!` field's
    // "stable and unique" contract and, downstream, React's `key={v.id}`
    // list rendering. The index is the parser's own running count, so it's
    // already unique and stable across reads (the list is append-only).
    id: `${index}:${target}:${vuln.PkgName}:${vuln.VulnerabilityID}`,
    vulnerabilityId: vuln.VulnerabilityID,
    pkgName: vuln.PkgName,
    installedVersion: vuln.InstalledVersion,
    fixedVersion: vuln.FixedVersion,
    severity: 'CRITICAL',
    title: vuln.Title,
    target,
  };
}
