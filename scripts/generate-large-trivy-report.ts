/**
 * Generates a synthetic Trivy-shaped JSON report for local OOM testing.
 *
 * Deliberately streams the file out with fs.createWriteStream instead of
 * building one giant object and JSON.stringify-ing it - the same
 * "never hold the whole thing in memory" discipline the actual service is
 * being tested for applies here too, and it means you can generate a
 * genuinely 500MB+ fixture without needing a huge heap yourself.
 *
 * Usage:
 *   npx ts-node scripts/generate-large-trivy-report.ts [targets] [vulnsPerTarget] [outFile]
 *
 * Example (~500MB, ~2000 targets x 2000 vulns):
 *   npx ts-node scripts/generate-large-trivy-report.ts 2000 2000 fixtures/huge-trivy-report.json
 */
import { createWriteStream } from 'node:fs';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;

const targets = parseInt(process.argv[2] ?? '200', 10);
const vulnsPerTarget = parseInt(process.argv[3] ?? '500', 10);
const outFile = process.argv[4] ?? 'fixtures/large-trivy-report.json';

mkdirSync(dirname(outFile), { recursive: true });
const out = createWriteStream(outFile);

function writeVuln(i: number, isLast: boolean): void {
  // Roughly 1 in 20 vulnerabilities is CRITICAL, so fixtures exercise the
  // filtering logic without every result being a match.
  const severity = i % 20 === 0 ? 'CRITICAL' : SEVERITIES[i % 3];
  const vuln = {
    VulnerabilityID: `CVE-2024-${10000 + i}`,
    PkgName: `package-${i % 50}`,
    InstalledVersion: `1.${i % 10}.0`,
    FixedVersion: `1.${(i % 10) + 1}.0`,
    Severity: severity,
    Title: `Synthetic vulnerability #${i} for fixture generation`,
    PrimaryURL: `https://example.invalid/CVE-2024-${10000 + i}`,
  };
  out.write(JSON.stringify(vuln) + (isLast ? '' : ','));
}

async function main(): Promise<void> {
  out.write('{"SchemaVersion":2,"ArtifactName":"nodegoat","ArtifactType":"filesystem","Results":[');

  for (let t = 0; t < targets; t++) {
    out.write(`{"Target":"package-lock.json#target-${t}","Class":"lang-pkgs","Type":"npm","Vulnerabilities":[`);
    for (let v = 0; v < vulnsPerTarget; v++) {
      writeVuln(t * vulnsPerTarget + v, v === vulnsPerTarget - 1);
    }
    out.write(t === targets - 1 ? ']}' : ']},');

    // Yield to the event loop periodically and respect backpressure so this
    // generator itself stays memory-bounded for very large fixtures.
    if (out.writableNeedDrain) {
      await new Promise<void>((resolve) => out.once('drain', resolve));
    }
  }

  out.write(']}');
  out.end();

  await new Promise<void>((resolve, reject) => {
    out.on('finish', resolve);
    out.on('error', reject);
  });

  // eslint-disable-next-line no-console
  console.log(`Wrote ${outFile} (${targets} targets x ${vulnsPerTarget} vulns/target)`);
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});
