import { Field, InputType } from '@nestjs/graphql';
import { Matches } from 'class-validator';

/**
 * Intentionally strict: only accepts an https GitHub repo URL, matching the
 * assignment's stated input ("GitHub Repository URL"). `git clone` would
 * technically accept ssh:// or git@ forms too, but scoping this down keeps
 * the surface area predictable for an unauthenticated public endpoint.
 */
// Each path segment must contain at least one alphanumeric character, which
// rejects `.` and `..` as an owner or repo name (e.g.
// `https://github.com/../..` previously validated). Not exploitable - the
// host is pinned and the local path is mkdtemp-generated - but it is
// validation surface with no legitimate use.
const GITHUB_REPO_URL_REGEX =
  /^https:\/\/github\.com\/(?=[\w.-]*\w)[\w.-]+\/(?=[\w.-]*\w)[\w.-]+?(?:\.git)?\/?$/;

@InputType()
export class StartScanInput {
  @Field()
  @Matches(GITHUB_REPO_URL_REGEX, {
    message: 'repositoryUrl must be a valid https://github.com/<owner>/<repo> URL',
  })
  repositoryUrl!: string;
}
