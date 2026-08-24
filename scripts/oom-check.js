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
