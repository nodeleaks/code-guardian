import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  TrivyStreamParserService,
  type CriticalVulnerabilitySink,
} from '../src/scan/trivy/trivy-stream-parser.service';
import type { CriticalVulnerability } from '../src/scan/interfaces/scan-record.interface';

/**
 * Stands in for the Redis-backed sink. Records each batch separately rather
 * than only the flattened result, so tests can assert on how the parser
 * chunked its output, not just on what it produced.
 */
function collectingSink(): CriticalVulnerabilitySink & {
  batches: CriticalVulnerability[][];
  all: () => CriticalVulnerability[];
} {
  const batches: CriticalVulnerability[][] = [];
  return {
    batches,
    all: () => batches.flat(),
    write: (batch) => {
      // Copy: the parser reuses/clears its buffer, and holding the same array
      // would let a later mutation rewrite what we already "stored".
      batches.push([...batch]);
      return Promise.resolve();
    },
  };
}

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

    const sink = collectingSink();
    const { totalCount } = await service.extractCriticalVulnerabilities(filePath, sink);

    expect(totalCount).toBe(2);
    expect(sink.all()).toHaveLength(2);
    expect(sink.all()).toEqual(
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

    const sink = collectingSink();
    const result = await service.extractCriticalVulnerabilities(file, sink);

    expect(result.totalCount).toBe(1);
    expect(sink.all()).toHaveLength(1);
    expect(sink.all()[0].target).toBe('good');
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

    await expect(
      service.extractCriticalVulnerabilities(filePath, collectingSink()),
    ).rejects.toMatchObject({
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

    const sink = collectingSink();
    const result = await service.extractCriticalVulnerabilities(filePath, sink);

    expect(result.totalCount).toBe(0);
    expect(sink.all()).toEqual([]);
  });

  it('rejects with a ScanEngineError when the file is not valid JSON', async () => {
    const filePath = writeFixture('broken.json', '{ this is not json');

    await expect(
      service.extractCriticalVulnerabilities(filePath, collectingSink()),
    ).rejects.toMatchObject({
      name: 'ScanEngineError',
      code: 'PARSE_FAILED',
    });
  });

  it('surfaces a sink failure as PARSE_FAILED rather than an unhandled rejection', async () => {
    // The sink writes to Redis in production, so it can fail independently of
    // the file being parsed. That failure happens inside a promise chain
    // started from a 'data' listener, which is exactly where an unhandled
    // rejection would hide - it has to reach the caller as a scan error.
    const targets = 20;
    const results = Array.from({ length: targets }, (_, t) => ({
      Target: `target-${t}`,
      Vulnerabilities: Array.from({ length: 100 }, (_, v) => ({
        VulnerabilityID: `CVE-${t}-${v}`,
        PkgName: `pkg-${v}`,
        Severity: 'CRITICAL',
      })),
    }));
    const filePath = writeFixture(
      'sink-failure.json',
      JSON.stringify({ SchemaVersion: 2, Results: results }),
    );

    const failingSink: CriticalVulnerabilitySink = {
      write: () => Promise.reject(new Error('redis is down')),
    };

    await expect(
      service.extractCriticalVulnerabilities(filePath, failingSink),
    ).rejects.toMatchObject({
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

    const sink = collectingSink();
    const { totalCount } = await service.extractCriticalVulnerabilities(filePath, sink);

    // Exactly one CRITICAL vulnerability was seeded per target.
    expect(totalCount).toBe(targets);
    expect(sink.all()).toHaveLength(targets);
  });

  it('stores every finding when CRITICAL findings vastly exceed one batch', async () => {
    // Adversarial fixture: every single vulnerability is CRITICAL. This used
    // to be the case where the parser capped what it kept; now nothing is
    // dropped, so the guarantee under test is the opposite one - everything
    // counted is also handed to the sink, and it arrives in bounded chunks
    // rather than as one 5,000-element array.
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

    const sink = collectingSink();
    const { totalCount } = await service.extractCriticalVulnerabilities(filePath, sink);

    const expected = targets * vulnsPerTarget;
    expect(totalCount).toBe(expected);
    // Nothing is truncated any more: every counted finding reached the sink.
    expect(sink.all()).toHaveLength(expected);

    // Memory boundedness is now a property of the batch size, so assert it
    // directly: no single batch may exceed the flush threshold.
    expect(sink.batches.length).toBeGreaterThan(1);
    for (const batch of sink.batches) {
      expect(batch.length).toBeLessThanOrEqual(500);
    }
  });

  it('preserves parse order across batches so pagination is stable', async () => {
    // Pages are LRANGE slices of an append-only list, so the order the parser
    // emits findings in is the order clients page through. If batches were
    // written concurrently this would scramble.
    const targets = 30;
    const vulnsPerTarget = 50; // 1,500 findings - several batches
    const results = Array.from({ length: targets }, (_, t) => ({
      Target: `target-${t}`,
      Vulnerabilities: Array.from({ length: vulnsPerTarget }, (_, v) => ({
        VulnerabilityID: `CVE-${String(t * vulnsPerTarget + v).padStart(5, '0')}`,
        PkgName: `pkg-${v}`,
        Severity: 'CRITICAL',
      })),
    }));
    const filePath = writeFixture(
      'ordered.json',
      JSON.stringify({ SchemaVersion: 2, Results: results }),
    );

    const sink = collectingSink();
    await service.extractCriticalVulnerabilities(filePath, sink);

    const ids = sink.all().map((v) => v.vulnerabilityId);
    expect(ids).toHaveLength(targets * vulnsPerTarget);
    expect(ids).toEqual([...ids].sort());
  });
});
