import { ExecutionContext, Injectable } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { ThrottlerGuard } from '@nestjs/throttler';

/**
 * ThrottlerGuard's default `getRequestResponse` reads req/res off the HTTP
 * context, which is empty for a GraphQL resolver - the request lives on the
 * Apollo context instead. This bridges the two so throttling actually
 * applies to mutations rather than silently no-opping.
 */
@Injectable()
export class GqlThrottlerGuard extends ThrottlerGuard {
  getRequestResponse(context: ExecutionContext) {
    const gqlCtx = GqlExecutionContext.create(context);
    const ctx = gqlCtx.getContext<{ req: Record<string, unknown>; res: Record<string, unknown> }>();
    return { req: ctx.req, res: ctx.res };
  }
}
