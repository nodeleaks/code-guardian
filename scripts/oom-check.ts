/**
 * Standalone proof that TrivyStreamParserService can process a 500MB+
 * Trivy report under a heap far smaller than the file itself.
 *
 * Deliberately bypasses the full Nest app (no Redis/BullMQ needed) so this
 * can run in isolation: it only exercises the streaming parser, which is
 * where the assignment's OOM constraint actually bites.
 *
 * Usage:
 *   node --max-old-space-size=150 -r ts-node/register scripts/oom-check.ts <file>
 */
import { TrivyStreamParserService } from '../src/scan/trivy/trivy-stream-parser.service';

async function main(): Promise<void> {
  const filePath = process.argv[2];
  if (!filePath) {
    console.error('Usage: oom-check.ts <path-to-trivy-report.json>');
    process.exit(1);
  }

  const service = new TrivyStreamParserService();
  const start = Date.now();
  const { vulnerabilities, totalCount, truncated } =
    await service.extractCriticalVulnerabilities(filePath);
  const seconds = ((Date.now() - start) / 1000).toFixed(1);
  const peakRssMb = (process.memoryUsage().rss / 1024 / 1024).toFixed(1);

  console.log(
    `OK: parsed in ${seconds}s, found ${totalCount} CRITICAL vulnerabilities (retained ${vulnerabilities.length}${
      truncated ? ', truncated' : ''
    }), peak RSS ~${peakRssMb}MB`,
  );
}

main().catch((err) => {
  console.error('FAILED:', err);
  process.exit(1);
});
