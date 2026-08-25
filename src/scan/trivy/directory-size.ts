import { readdir, lstat } from 'node:fs/promises';
import { join } from 'node:path';

/**
 * Recursively sums the on-disk size of `dir`.
 *
 * Uses `lstat` and never follows symlinks: a cloned repository is untrusted
 * content, and a symlink pointing at something large (or at a cycle) must
 * not be counted or descended into.
 */
export async function directorySizeBytes(dir: string): Promise<number> {
  let total = 0;

  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.isSymbolicLink()) {
      continue;
    }
    if (entry.isDirectory()) {
      total += await directorySizeBytes(path);
      continue;
    }
    if (entry.isFile()) {
      const stats = await lstat(path);
      total += stats.size;
    }
  }

  return total;
}
