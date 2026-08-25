import { useEffect, useRef, useState } from 'react';
import { errorMessage, getScan, isValidRepositoryUrl, startScan, type Scan } from './api';

const POLL_INTERVAL_MS = 2000;
const IN_PROGRESS_STATUSES = new Set(['QUEUED', 'SCANNING']);
// After this many consecutive failed polls, stop retrying automatically and
// let the user decide (rather than silently hammering a dead API forever).
const MAX_CONSECUTIVE_POLL_FAILURES = 3;

export default function App() {
  const [repositoryUrl, setRepositoryUrl] = useState('');
  const [scan, setScan] = useState<Scan | null>(null);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pollingStopped, setPollingStopped] = useState(false);

  // Guards against a poll response landing after a newer scan has started
  // (or after unmount) - only apply a response if it's still for the scan
  // we're currently tracking.
  const activeScanId = useRef<string | null>(null);
  const pollFailures = useRef(0);

  useEffect(() => {
    if (!scan || !IN_PROGRESS_STATUSES.has(scan.status) || pollingStopped) {
      return;
    }

    const scanId = scan.id;
    const timer = setInterval(() => {
      getScan(scanId)
        .then((updated) => {
          if (activeScanId.current !== scanId) return;

          if (!updated) {
            // The record vanished - most likely its TTL expired in Redis.
            // Retrying forever would be pointless, so stop and say why.
            setPollingStopped(true);
            setError('This scan could no longer be found (it may have expired). Start a new one.');
            return;
          }

          pollFailures.current = 0;
          setError(null);
          setScan(updated);
        })
        .catch((err: unknown) => {
          if (activeScanId.current !== scanId) return;

          pollFailures.current += 1;
          if (pollFailures.current >= MAX_CONSECUTIVE_POLL_FAILURES) {
            setPollingStopped(true);
            setError(`Lost connection while polling: ${errorMessage(err)}`);
          } else {
            setError(`Temporary connection issue, retrying… (${errorMessage(err)})`);
          }
        });
    }, POLL_INTERVAL_MS);

    return () => clearInterval(timer);
  }, [scan, pollingStopped]);

  async function handleStart(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = repositoryUrl.trim();
    if (!trimmed || starting) return;

    if (!isValidRepositoryUrl(trimmed)) {
      setError('Enter a valid GitHub repo URL, e.g. https://github.com/owner/repo');
      return;
    }

    setStarting(true);
    setError(null);
    setScan(null);
    setPollingStopped(false);
    pollFailures.current = 0;
    activeScanId.current = null;

    try {
      const started = await startScan(trimmed);
      activeScanId.current = started.id;
      // Seed the result from the mutation's own response (id + status =
      // QUEUED) rather than an extra getScan round trip - one less network
      // call that could fail, and the poll loop above fills in the rest.
      setScan({
        id: started.id,
        repositoryUrl: trimmed,
        status: started.status,
        criticalVulnerabilities: [],
        criticalVulnerabilityCount: 0,
        criticalVulnerabilitiesTruncated: false,
        errorMessage: null,
      });
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setStarting(false);
    }
  }

  function handleRetryPolling() {
    pollFailures.current = 0;
    setError(null);
    setPollingStopped(false);
  }

  const busy = starting || (scan !== null && IN_PROGRESS_STATUSES.has(scan.status) && !pollingStopped);
  const canRetryPolling =
    pollingStopped && scan !== null && IN_PROGRESS_STATUSES.has(scan.status) && !!error;

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

      {error && (
        <p className="error">
          {error}
          {canRetryPolling && (
            <button type="button" className="retry-button" onClick={handleRetryPolling}>
              Retry
            </button>
          )}
        </p>
      )}

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
