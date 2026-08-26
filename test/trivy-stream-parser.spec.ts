import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TrivyStreamParserService } from '../src/scan/trivy/trivy-stream-parser.service';

describe('TrivyStreamParserService', () => {
  let dir: string;
  let service: TrivyStreamParserService;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'trivy-parser-test-'));
    service = new TrivyStreamParserService();
  });

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function writeFixture(fileName: string, contents: string): string {
    const filePath = join(dir, fileName);
    writeFileSync(filePath, contents);
    return filePath;
  }

  it('extracts only CRITICAL vulnerabilities, tagged with their target', async () => {
    const filePath = writeFixture(
      'basic.json',
      JSON.stringify({
        SchemaVersion: 2,
        ArtifactName: 'nodegoat',
        Results: [
          {
            Target: 'package-lock.json',
            Class: 'lang-pkgs',
            Type: 'npm',
            Vulnerabilities: [
              { VulnerabilityID: 'CVE-1', PkgName: 'lodash', Severity: 'LOW' },
              {
                VulnerabilityID: 'CVE-2',
                PkgName: 'express',
                Severity: 'CRITICAL',
                InstalledVersion: '3.0.0',
                FixedVersion: '4.0.0',
                Title: 'RCE',
              },
            ],
          },
          {
            // No Vulnerabilities field at all (e.g. a config/secret result) -
            // must be skipped without throwing.
            Target: 'Dockerfile',
            Class: 'config',
            Type: 'dockerfile',
          },
          {
            Target: 'go.sum',
            Vulnerabilities: [
              { VulnerabilityID: 'CVE-3', PkgName: 'x/net', Severity: 'CRITICAL' },
              { VulnerabilityID: 'CVE-4', PkgName: 'x/net', Severity: 'HIGH' },
            ],
          },
        ],
      }),
    );

    const { vulnerabilities, totalCount, truncated } =
      await service.extractCriticalVulnerabilities(filePath);

    expect(totalCount).toBe(2);
    expect(truncated).toBe(false);
    expect(vulnerabilities).toHaveLength(2);
    expect(vulnerabilities).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          vulnerabilityId: 'CVE-2',
          pkgName: 'express',
          target: 'package-lock.json',
          severity: 'CRITICAL',
        }),
        expect.objectContaining({
          vulnerabilityId: 'CVE-3',
          pkgName: 'x/net',
          target: 'go.sum',
          severity: 'CRITICAL',
        }),
      ]),
    );
  });

  it('ignores a non-array Vulnerabilities value instead of crashing', async () => {
    // A `?.length` truthiness guard passes for an object carrying a `length`
    // property and then throws on `for...of`. That throw happens inside the
    // stream's 'data' listener, escaping the promise's reject and surfacing
    // as an uncaught exception rather than a PARSE_FAILED.
    const file = writeFixture(
      'non-array-vulns.json',
      JSON.stringify({
        Results: [
          { Target: 'bad', Vulnerabilities: { length: 3 } },
          {
            Target: 'good',
            Vulnerabilities: [
              { VulnerabilityID: 'CVE-1', PkgName: 'p', Severity: 'CRITICAL' },
            ],
          },
        ],
      }),
    );

    const result = await service.extractCriticalVulnerabilities(file);

    expect(result.totalCount).toBe(1);
    expect(result.vulnerabilities).toHaveLength(1);
    expect(result.vulnerabilities[0].target).toBe('good');
  });

  it('rejects a well-formed JSON file that has no Results key', async () => {
    // The dangerous shape: trivy exits 0 and writes valid JSON that isn't a
    // filesystem-scan report. `pick` yields nothing, so without an explicit
    // check this resolves as "0 CRITICAL" and the scan is marked FINISHED -
    // a clean bill of health for a repository nobody actually scanned.
    const filePath = writeFixture(
      'no-results-key.json',
      JSON.stringify({ SchemaVersion: 2, ArtifactName: 'nodegoat' }),
    );

    await expect(service.extractCriticalVulnerabilities(filePath)).rejects.toMatchObject({
      name: 'ScanEngineError',
      code: 'PARSE_FAILED',
    });
  });

  it('accepts an empty Results array as a genuinely clean scan', async () => {
    // The boundary the check above must not cross. After streamArray() this
    // is indistinguishable from a missing Results key - both yield zero
    // elements - so anything based on counting emitted targets would reject
    // a legitimately clean repository. Only the token stream separates them.
    const filePath = writeFixture('empty-results.json', JSON.stringify({ Results: [] }));

    const result = await service.extractCriticalVulnerabilities(filePath);

    expect(result.totalCount).toBe(0);
    expect(result.truncated).toBe(false);
    expect(result.vulnerabilities).toEqual([]);
  });

  it('rejects with a ScanEngineError when the file is not valid JSON', async () => {
    const filePath = writeFixture('broken.json', '{ this is not json');

    await expect(service.extractCriticalVulnerabilities(filePath)).rejects.toMatchObject({
      name: 'ScanEngineError',
      code: 'PARSE_FAILED',
    });
  });

  it('scales to many targets/vulnerabilities via the streaming pipeline', async () => {
    const targets = 500;
    const vulnsPerTarget = 40;
    const results = Array.from({ length: targets }, (_, t) => ({
      Target: `target-${t}`,
      Vulnerabilities: Array.from({ length: vulnsPerTarget }, (_, v) => ({
        VulnerabilityID: `CVE-${t}-${v}`,
        PkgName: `pkg-${v}`,
        Severity: v === 0 ? 'CRITICAL' : 'LOW',
      })),
    }));
    const filePath = writeFixture('large.json', JSON.stringify({ SchemaVersion: 2, Results: results }));

    const { vulnerabilities, totalCount, truncated } =
      await service.extractCriticalVulnerabilities(filePath);

    // Exactly one CRITICAL vulnerability was seeded per target, and 500 is
    // comfortably under the retention cap, so nothing should be truncated.
    expect(totalCount).toBe(targets);
    expect(vulnerabilities).toHaveLength(targets);
    expect(truncated).toBe(false);
  });

  it('caps the retained list and reports truncation when CRITICAL findings vastly exceed the cap', async () => {
    // Adversarial fixture: every single vulnerability is CRITICAL, well
    // beyond the MAX_RETAINED_VULNERABILITIES cap - this is the scenario
    // the cap exists to guard against (see trivy-stream-parser.service.ts).
    const targets = 50;
    const vulnsPerTarget = 100; // 5,000 CRITICAL findings total
    const results = Array.from({ length: targets }, (_, t) => ({
      Target: `target-${t}`,
      Vulnerabilities: Array.from({ length: vulnsPerTarget }, (_, v) => ({
        VulnerabilityID: `CVE-${t}-${v}`,
        PkgName: `pkg-${v}`,
        Severity: 'CRITICAL',
      })),
    }));
    const filePath = writeFixture(
      'adversarial.json',
      JSON.stringify({ SchemaVersion: 2, Results: results }),
    );

    const { vulnerabilities, totalCount, truncated } =
      await service.extractCriticalVulnerabilities(filePath);

    expect(totalCount).toBe(targets * vulnsPerTarget);
    expect(vulnerabilities.length).toBeLessThan(totalCount);
    expect(truncated).toBe(true);
  });
});
