/**
 * Rejects with `TimeoutError` if `promise` hasn't settled within `ms`.
 *
 * Note what this does NOT do: it cannot cancel the underlying operation. For
 * an ioredis command the command stays in the client's offline queue and may
 * still run later. The point here is bounding how long a caller waits, which
 * matters because some of the connections this service uses are configured to
 * retry forever (BullMQ sets `maxRetriesPerRequest: null` on its own
 * connection), so a Redis outage otherwise produces a request that never
 * settles at all rather than one that fails.
 */
export class TimeoutError extends Error {
  constructor(label: string, ms: number) {
    super(`${label} did not complete within ${ms}ms`);
    this.name = 'TimeoutError';
  }
}

export async function withTimeout<T>(
  promise: PromiseLike<T>,
  ms: number,
  label: string,
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;

  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new TimeoutError(label, ms)), ms);
      }),
    ]);
  } finally {
    // Without this the pending timer keeps the event loop alive for up to
    // `ms` after a fast success - enough to make process shutdown hang.
    clearTimeout(timer);
  }
}
