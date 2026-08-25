import { useEffect, useRef, useState } from 'react';
import { getScan, startScan, type Scan } from './api';

const POLL_INTERVAL_MS = 2000;
const IN_PROGRESS_STATUSES = new Set(['QUEUED', 'SCANNING']);

export default function App() {
  const [repositoryUrl, setRepositoryUrl] = useState('');
  const [scan, setScan] = useState<Scan | null>(null);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Guards against a poll response landing after a newer scan has started
  // (or after unmount) - only apply a response if it's still for the scan
  // we're currently tracking.
  const activeScanId = useRef<string | null>(null);

  useEffect(() => {
    if (!scan || !IN_PROGRESS_STATUSES.has(scan.status)) {
      return;
    }

    const scanId = scan.id;
    const timer = setInterval(() => {
      getScan(scanId)
        .then((updated) => {
          if (activeScanId.current !== scanId || !updated) return;
          setScan(updated);
        })
        .catch((err: unknown) => {
          if (activeScanId.current !== scanId) return;
          setError(err instanceof Error ? err.message : String(err));
        });
    }, POLL_INTERVAL_MS);

    return () => clearInterval(timer);
  }, [scan]);

  async function handleStart(e: React.FormEvent) {
    e.preventDefault();
    if (!repositoryUrl.trim() || starting) return;

    setStarting(true);
    setError(null);
    setScan(null);
    activeScanId.current = null;

    try {
      const started = await startScan(repositoryUrl.trim());
      activeScanId.current = started.id;
      const full = await getScan(started.id);
      setScan(full);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setStarting(false);
    }
  }

  const busy = starting || (scan !== null && IN_PROGRESS_STATUSES.has(scan.status));

  return (
    <main className="app">
      <h1>Code Guardian</h1>
      <p className="subtitle">Scan a public GitHub repository for CRITICAL vulnerabilities.</p>

      <form onSubmit={handleStart} className="scan-form">
        <input
          type="url"
          placeholder="https://github.com/owner/repo"
          value={repositoryUrl}
          onChange={(e) => setRepositoryUrl(e.target.value)}
          disabled={busy}
          required
        />
        <button type="submit" disabled={busy}>
          {starting ? 'Starting…' : 'Start'}
        </button>
      </form>

      {error && <p className="error">{error}</p>}

      {scan && <ScanResult scan={scan} />}
    </main>
  );
}

function ScanResult({ scan }: { scan: Scan }) {
  return (
    <section className="result">
      <div className="status-row">
        <span>Repository: {scan.repositoryUrl}</span>
        <span className={`status status--${scan.status.toLowerCase()}`}>{scan.status}</span>
      </div>

      {IN_PROGRESS_STATUSES.has(scan.status) && <p>Polling every 2 seconds…</p>}

      {scan.status === 'FAILED' && <p className="error">{scan.errorMessage ?? 'Scan failed.'}</p>}

      {scan.status === 'FINISHED' && (
        <>
          <p>
            {scan.criticalVulnerabilityCount} CRITICAL vulnerabilit
            {scan.criticalVulnerabilityCount === 1 ? 'y' : 'ies'} found
            {scan.criticalVulnerabilitiesTruncated && ' (list truncated)'}
          </p>

          {scan.criticalVulnerabilities.length > 0 && (
            <table>
              <thead>
                <tr>
                  <th>CVE</th>
                  <th>Package</th>
                  <th>Installed</th>
                  <th>Fixed in</th>
                  <th>Target</th>
                </tr>
              </thead>
              <tbody>
                {scan.criticalVulnerabilities.map((v) => (
                  <tr key={v.id}>
                    <td title={v.title ?? undefined}>{v.vulnerabilityId}</td>
                    <td>{v.pkgName}</td>
                    <td>{v.installedVersion ?? '—'}</td>
                    <td>{v.fixedVersion ?? '—'}</td>
                    <td>{v.target}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </section>
  );
}
