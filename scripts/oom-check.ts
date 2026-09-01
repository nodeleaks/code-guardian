/**
 * Standalone proof that TrivyStreamParserService can process a 500MB+
 * Trivy report under a heap far smaller than the file itself.
 *
 * Deliberately bypasses the full Nest app (no Redis/BullMQ needed) so this
 * can run in isolation: it only exercises the streaming parser, which is
 * where the assignment's OOM constraint actually bites. The sink below stands
 * in for the Redis-backed one used in production - same code path through the
 * parser, without needing a Redis to point it at.
 *
 * Usage:
 *   node --max-old-space-size=150 -r ts-node/register scripts/oom-check.ts <file>
 */
import { TrivyStreamParserService } from '../src/scan/trivy/trivy-stream-parser.service';
import { CriticalVulnerability } from '../src/scan/interfaces/scan-record.interface';

async function main(): Promise<void> {
  const filePath = process.argv[2];
  if (!filePath) {
    console.error('Usage: oom-check.ts <path-to-trivy-report.json>');
    process.exit(1);
  }

  const service = new TrivyStreamParserService();

  // Counts batches and drops them, exactly as the real sink drops them once
  // Redis has taken them. Deliberately not accumulating: retaining the
  // findings here would measure this script's memory use rather than the
  // parser's, and the parser is what the heap cap is meant to test.
  let batches = 0;
  let largestBatch = 0;
  const sink = {
    write: (batch: CriticalVulnerability[]): Promise<void> => {
      if (batch.length > 0) {
        batches += 1;
        largestBatch = Math.max(largestBatch, batch.length);
      }
      return Promise.resolve();
    },
  };

  const start = Date.now();
  const { totalCount } = await service.extractCriticalVulnerabilities(filePath, sink);
  const seconds = ((Date.now() - start) / 1000).toFixed(1);
  const peakRssMb = (process.memoryUsage().rss / 1024 / 1024).toFixed(1);

  console.log(
    `OK: parsed in ${seconds}s, streamed ${totalCount} CRITICAL vulnerabilities to the sink ` +
      `in ${batches} batch(es), largest batch ${largestBatch}, peak RSS ~${peakRssMb}MB`,
  );
}

main().catch((err) => {
  console.error('FAILED:', err);
  process.exit(1);
});
