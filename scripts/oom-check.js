/**
 * Plain-JS OOM proof, run against the COMPILED output (dist/) so the
 * TypeScript compiler itself (which is memory-hungry) is not part of what's
 * being measured under the constrained heap - only the actual runtime
 * streaming logic is.
 *
 * Usage: node --max-old-space-size=150 scripts/oom-check.js <file>
 */
require('reflect-metadata');
const { TrivyStreamParserService } = require('../dist/scan/trivy/trivy-stream-parser.service');

async function main() {
  const filePath = process.argv[2];
  if (!filePath) {
    console.error('Usage: oom-check.js <path-to-trivy-report.json>');
    process.exit(1);
  }

  const service = new TrivyStreamParserService();

  // Stands in for the Redis-backed sink used in production: counts each batch
  // and drops it. Deliberately not accumulating - retaining the findings here
  // would measure this script's memory use rather than the parser's, and the
  // parser is what the heap cap exists to test.
  let batches = 0;
  let largestBatch = 0;
  const sink = {
    write: (batch) => {
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
