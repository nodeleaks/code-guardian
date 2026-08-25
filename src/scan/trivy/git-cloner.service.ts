import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import simpleGit from 'simple-git';
import { AppConfig } from '../../config/configuration';
import { ScanEngineError } from '../../common/errors/scan-engine.error';
import { directorySizeBytes } from './directory-size';

// simple-git refuses to forward any of these env vars via `.env()` unless
// the matching `allowUnsafe*` flag is set - they're all ways an environment
// can redirect what a "git clone" actually does (pager/editor/ssh/proxy
// overrides, alternate config files). We don't want any of them honored for
// an automated clone of an untrusted URL anyway, so they're stripped rather
// than allowed through. Simply not spreading process.env at all isn't an
// option either: simple-git's .env() *replaces* the child process' env
// rather than merging with it, so PATH/HOME/etc. would be lost and git
// itself would stop working.
const UNSAFE_GIT_ENV_KEYS = new Set([
  'EDITOR',
  'GIT_ASKPASS',
  'GIT_CONFIG',
  'GIT_CONFIG_COUNT',
  'GIT_CONFIG_GLOBAL',
  'GIT_CONFIG_SYSTEM',
  'GIT_EDITOR',
  'GIT_EXEC_PATH',
  'GIT_EXTERNAL_DIFF',
  'GIT_PAGER',
  'GIT_PROXY_COMMAND',
  'GIT_SEQUENCE_EDITOR',
  'GIT_SSH',
  'GIT_SSH_COMMAND',
  'GIT_TEMPLATE_DIR',
  'PAGER',
  'PREFIX',
  'SSH_ASKPASS',
]);

function safeCloneEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined && !UNSAFE_GIT_ENV_KEYS.has(key.toUpperCase())) {
      env[key] = value;
    }
  }
  return env;
}

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
          ...safeCloneEnv(),
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
