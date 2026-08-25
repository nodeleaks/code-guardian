import { ScanEngineError } from '../src/common/errors/scan-engine.error';
import { toPublicErrorMessage } from '../src/common/errors/scan-error-messages';

describe('toPublicErrorMessage', () => {
  it('never echoes the underlying diagnostic message', () => {
    const leaky = new ScanEngineError(
      'trivy exited with code 1: FATAL failed to write /tmp/trivy-report-abc-123.json',
      'TRIVY_EXEC_FAILED',
    );

    const publicMessage = toPublicErrorMessage(leaky);

    expect(publicMessage).not.toContain('/tmp/');
    expect(publicMessage).not.toContain('trivy-report');
    expect(publicMessage).not.toContain('exited with code');
  });

  it('never echoes a cloned repository path or git stderr', () => {
    const leaky = new ScanEngineError(
      'Failed to clone repository "https://github.com/o/r": fatal: could not read Username for https://github.com',
      'CLONE_FAILED',
    );

    const publicMessage = toPublicErrorMessage(leaky);

    expect(publicMessage).not.toContain('fatal:');
    expect(publicMessage).not.toContain('Username');
  });

  it('maps each known code to a distinct, non-empty message', () => {
    const codes = [
      'CLONE_FAILED',
      'REPO_TOO_LARGE',
      'TRIVY_SPAWN_FAILED',
      'TRIVY_EXEC_FAILED',
      'PARSE_FAILED',
      'DISK_FULL',
      'TIMED_OUT',
      'UNKNOWN',
    ] as const;

    const messages = codes.map((code) => toPublicErrorMessage(new ScanEngineError('x', code)));

    for (const message of messages) {
      expect(message.length).toBeGreaterThan(0);
    }
    expect(new Set(messages).size).toBe(codes.length);
  });

  it('falls back to the generic message for a non-ScanEngineError', () => {
    expect(toPublicErrorMessage(new Error('raw internals'))).toBe(
      'The scan failed for an unexpected reason.',
    );
    expect(toPublicErrorMessage('some string')).toBe('The scan failed for an unexpected reason.');
  });
});
