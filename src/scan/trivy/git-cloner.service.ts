import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import simpleGit from 'simple-git';
import { AppConfig } from '../../config/configuration';
import { ScanEngineError } from '../../common/errors/scan-engine.error';
import { directorySizeBytes } from './directory-size';

/**
 * Clones a repository into a fresh temp directory. Uses a shallow
 * (--depth 1) clone: Trivy's filesystem scanner only needs the working
 * tree, not history, and a shallow clone bounds the disk/network cost
 * regardless of how large the target repo's history is.
 */
@Injectable()
export class GitClonerService {
  private readonly logger = new Logger(GitClonerService.name);
  private readonly timeoutMs: number;
  private readonly maxRepoSizeBytes: number;

  constructor(config: ConfigService<AppConfig, true>) {
    this.timeoutMs = config.get('scan.timeoutMs', { infer: true });
    this.maxRepoSizeBytes = config.get('scan.maxRepoSizeMb', { infer: true }) * 1024 * 1024;
  }

  async cloneToTemp(repositoryUrl: string): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), 'code-guardian-repo-'));

    try {
      this.logger.log(`Cloning ${repositoryUrl} into ${dir}`);

      await simpleGit({
        timeout: { block: this.timeoutMs },
      })
        .env({
          ...process.env,
          // Without this, a private/nonexistent repo makes git try to
          // acquire credentials. Wherever a TTY is reachable that blocks
          // indefinitely, and since the worker runs one job at a time a
          // single such URL wedges all scanning. Fail fast instead.
          // (GIT_ASKPASS would belt-and-brace this, but simple-git rejects
          // it unless allowUnsafeAskPass is set - not worth that trade.)
          GIT_TERMINAL_PROMPT: '0',
          GIT_CONFIG_NOSYSTEM: '1',
        })
        .clone(repositoryUrl, dir, ['--depth', '1', '--single-branch']);

      await this.assertWithinSizeLimit(dir);

      return dir;
    } catch (err) {
      await rm(dir, { recursive: true, force: true });

      if (err instanceof ScanEngineError) {
        throw err;
      }

      const message = err instanceof Error ? err.message : String(err);
      const code = /enospc|no space left/i.test(message)
        ? 'DISK_FULL'
        : /timeout|timed out/i.test(message)
          ? 'TIMED_OUT'
          : 'CLONE_FAILED';
      throw new ScanEngineError(`Failed to clone repository "${repositoryUrl}": ${message}`, code, err);
    }
  }

  /**
   * `--depth 1` bounds history, not working-tree size - a repo with a
   * multi-GB tree still lands on disk in full. Checked after the clone (git
   * has no reliable pre-flight size for an arbitrary remote) but before
   * trivy runs, so an oversized repo costs one clone rather than a clone
   * plus a full scan.
   */
  private async assertWithinSizeLimit(dir: string): Promise<void> {
    const sizeBytes = await directorySizeBytes(dir);
    if (sizeBytes > this.maxRepoSizeBytes) {
      const sizeMb = Math.round(sizeBytes / 1024 / 1024);
      const limitMb = Math.round(this.maxRepoSizeBytes / 1024 / 1024);
      throw new ScanEngineError(
        `Cloned repository is ${sizeMb}MB, which exceeds the ${limitMb}MB limit`,
        'REPO_TOO_LARGE',
      );
    }
  }
}
