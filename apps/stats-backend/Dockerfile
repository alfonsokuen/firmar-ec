# syntax=docker/dockerfile:1.7
# firma-ec stats-backend — multi-stage Node 22 alpine
# Public usage-stats service (Fastify + Prisma + Redis). Replaces the KV worker.

# ---------- deps ----------
FROM node:22.23.4-alpine AS deps
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate
WORKDIR /app
# Workspace manifests first (better layer cache). .npmrc is REQUIRED here: it
# carries auto-install-peers=false, which must match the lockfile's
# settings.autoInstallPeers — without it the build's pnpm defaults to true and
# `--frozen-lockfile` aborts with ERR_PNPM_LOCKFILE_CONFIG_MISMATCH.
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml .npmrc ./
COPY apps/stats-backend/package.json apps/stats-backend/
RUN pnpm install --frozen-lockfile

# ---------- build ----------
FROM node:22.23.4-alpine AS build
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate
WORKDIR /app
# Bring node_modules from deps stage (workspace + per-package)
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/apps/stats-backend/node_modules ./apps/stats-backend/node_modules
# Copy source
COPY tsconfig.base.json tsconfig.json .npmrc ./
COPY apps/stats-backend ./apps/stats-backend
# Generate Prisma client
RUN pnpm -F @firma-ec/stats-backend prisma:generate
# Bundle backend
RUN pnpm -F @firma-ec/stats-backend build

# ---------- runtime ----------
FROM node:22.23.4-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000
ENV HOST=0.0.0.0
RUN apk upgrade --no-cache ca-certificates && apk add --no-cache wget tini
# Preserve the pnpm workspace layout so the externalized @prisma/client (and its
# native linux-musl query engine, generated in the build stage for THIS platform)
# resolves at runtime via the app's node_modules symlinks into the root .pnpm
# store. Prisma 6 + pnpm puts the generated client INSIDE @prisma/client (there is
# no separate .prisma dir), so a targeted copy is unreliable — copy the tree.
# Running from apps/stats-backend/dist keeps the resolution path intact.
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/apps/stats-backend/node_modules ./apps/stats-backend/node_modules
COPY --from=build /app/apps/stats-backend/prisma ./apps/stats-backend/prisma
COPY --from=build /app/apps/stats-backend/dist ./apps/stats-backend/dist
USER node
EXPOSE 3000
# Liveness ONLY (process up). Readiness (DB/Redis) lives at /healthz and is for
# the LB + observability — a dependency blip must NOT kill the container (else a
# transient DB/Redis hiccup triggers a pointless restart/rollback loop).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- http://localhost:3000/livez || exit 1
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "apps/stats-backend/dist/index.js"]
