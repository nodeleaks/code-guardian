import { Injectable, Logger } from '@nestjs/common';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import simpleGit from 'simple-git';
import { ScanEngineError } from '../../common/errors/scan-engine.error';

/**
 * Clones a repository into a fresh temp directory. Uses a shallow
 * (--depth 1) clone: Trivy's filesystem scanner only needs the working
 * tree, not history, and a shallow clone bounds the disk/network cost
 * regardless of how large the target repo's history is.
 */
@Injectable()
export class GitClonerService {
  private readonly logger = new Logger(GitClonerService.name);

  async cloneToTemp(repositoryUrl: string): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), 'code-guardian-repo-'));

    try {
      this.logger.log(`Cloning ${repositoryUrl} into ${dir}`);
      await simpleGit().clone(repositoryUrl, dir, ['--depth', '1', '--single-branch']);
      return dir;
    } catch (err) {
      await rm(dir, { recursive: true, force: true });

      const message = err instanceof Error ? err.message : String(err);
      const code = /enospc|no space left/i.test(message) ? 'DISK_FULL' : 'CLONE_FAILED';
      throw new ScanEngineError(`Failed to clone repository "${repositoryUrl}": ${message}`, code, err);
    }
  }
}
