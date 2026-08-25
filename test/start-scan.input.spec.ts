import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';
import { StartScanInput } from '../src/scan/dto/start-scan.input';

describe('StartScanInput', () => {
  async function validateInput(url: string): Promise<number> {
    const input = plainToInstance(StartScanInput, { repositoryUrl: url });
    const errors = await validate(input);
    return errors.length;
  }

  describe('valid URLs', () => {
    it('accepts https://github.com/owner/repo', async () => {
      expect(await validateInput('https://github.com/owner/repo')).toBe(0);
    });

    it('accepts https://github.com/owner/repo.git', async () => {
      expect(await validateInput('https://github.com/owner/repo.git')).toBe(0);
    });

    it('accepts https://github.com/owner/repo/', async () => {
      expect(await validateInput('https://github.com/owner/repo/')).toBe(0);
    });

    it('accepts owner/repo names with dots and dashes', async () => {
      expect(await validateInput('https://github.com/owner.name/repo-name')).toBe(0);
    });

    it('accepts owner/repo names with underscores', async () => {
      expect(await validateInput('https://github.com/owner_name/repo_name')).toBe(0);
    });

    it('accepts names with mixed alphanumerics', async () => {
      expect(await validateInput('https://github.com/owner123/repo456')).toBe(0);
    });
  });

  describe('invalid URLs', () => {
    it('rejects http (non-https)', async () => {
      expect(await validateInput('http://github.com/owner/repo')).toBeGreaterThan(0);
    });

    it('rejects wrong host', async () => {
      expect(await validateInput('https://gitlab.com/owner/repo')).toBeGreaterThan(0);
    });

    it('rejects missing repo segment', async () => {
      expect(await validateInput('https://github.com/owner')).toBeGreaterThan(0);
    });

    it('rejects ssh form git@github.com:owner/repo', async () => {
      expect(await validateInput('git@github.com:owner/repo')).toBeGreaterThan(0);
    });

    it('rejects ssh:// form', async () => {
      expect(await validateInput('ssh://github.com/owner/repo')).toBeGreaterThan(0);
    });

    it('rejects empty string', async () => {
      expect(await validateInput('')).toBeGreaterThan(0);
    });

    it('rejects plain text', async () => {
      expect(await validateInput('owner/repo')).toBeGreaterThan(0);
    });

    it('rejects .. as a path segment', async () => {
      expect(await validateInput('https://github.com/../..')).toBeGreaterThan(0);
    });

    it('rejects . as a path segment', async () => {
      expect(await validateInput('https://github.com/./.')).toBeGreaterThan(0);
    });

    it('rejects .. as the repo segment only', async () => {
      expect(await validateInput('https://github.com/owner/..')).toBeGreaterThan(0);
    });

    it('rejects missing .com', async () => {
      expect(await validateInput('https://github/owner/repo')).toBeGreaterThan(0);
    });
  });

  it('exposes the regex constraint in error messages', async () => {
    const input = plainToInstance(StartScanInput, { repositoryUrl: 'invalid' });
    const errors = await validate(input);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0].constraints).toHaveProperty('matches');
  });
});
