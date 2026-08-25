# syntax=docker/dockerfile:1

# ---- deps: install ALL dependencies (incl. devDependencies) for the build step ----
FROM node:24-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

# ---- build: compile TypeScript -> dist/ ----
FROM deps AS build
WORKDIR /app
COPY tsconfig.json tsconfig.build.json nest-cli.json ./
COPY src ./src
RUN npm run build

# ---- prod-deps: a second, production-only install (no devDependencies) ----
FROM node:24-slim AS prod-deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# ---- runtime: the actual image that ships ----
FROM node:24-slim AS runtime
WORKDIR /app

# Trivy needs its own binary, and `simple-git` shells out to a real `git`
# binary rather than reimplementing it - both are installed here so the
# service can run `git clone` and `trivy fs` exactly as it does outside
# Docker (see git-cloner.service.ts / trivy-runner.service.ts). Pin
# TRIVY_VERSION for reproducible builds; left unset it installs whatever is
# currently latest.
ARG TRIVY_VERSION=""
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
       | sh -s -- -b /usr/local/bin ${TRIVY_VERSION} \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production
ENV TRIVY_BINARY_PATH=trivy

# Trivy's vulnerability DB is a ~1.3GB bolt file, and *downloading* it is by
# far the most memory-hungry thing this image does: extracting the tarball to
# disk pushed the cgroup to ~1GB in testing (mostly dirty page cache), while
# the scan itself peaks around 47MB. So the cache lives on its own mount
# point, populated once by the `trivy-db` init service in docker-compose.yml
# and shared with the app read-write - the app itself runs with
# TRIVY_SKIP_DB_UPDATE=true and never pays the download cost. That's what
# makes the 200m limit on `app` an honest test of the streaming pipeline
# rather than a coin flip against the DB downloader.
ENV TRIVY_CACHE_DIR=/trivy-cache

COPY --from=prod-deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./

# Run as a non-root user. Repo clones and Trivy reports land under the
# system temp dir (os.tmpdir()) at runtime, so that's covered by /tmp being
# world-writable by default - but /app itself is still owned by root at
# this point (everything above ran as root), so it's chown'd explicitly too.
# Without this, anything the app tries to write under its own working
# directory (e.g. GraphQLModule's autoSchemaFile in non-production configs)
# fails with EACCES.
# /trivy-cache must exist in the image *and* be owned by appuser: Docker
# seeds a fresh named volume from the image's content at that path, ownership
# included. Without this the volume comes up root-owned and trivy dies with
# `mkdir /trivy-cache/db: permission denied`.
RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /trivy-cache \
    && chown -R appuser:appuser /app /trivy-cache
USER appuser

EXPOSE 3000
CMD ["node", "dist/main.js"]
