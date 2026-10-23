# syntax=docker/dockerfile:1.7
# firma-ec inbox-backend — multi-stage Node 22 alpine
# F3.5 T29 — WhatsApp inbox (Fastify + Prisma + Redis + R2)

# ---------- deps ----------
FROM node:22.23.4-alpine AS deps
RUN corepack enable && corepack prepare pnpm@latest --activate
WORKDIR /app
# Workspace manifests first (better layer cache)
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml ./
COPY apps/inbox-backend/package.json apps/inbox-backend/
COPY packages/inbox-crypto/package.json packages/inbox-crypto/
RUN pnpm install --frozen-lockfile

# ---------- build ----------
FROM node:22.23.4-alpine AS build
RUN corepack enable && corepack prepare pnpm@latest --activate
WORKDIR /app
# Bring node_modules from deps stage (workspace + per-package)
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/apps/inbox-backend/node_modules ./apps/inbox-backend/node_modules
COPY --from=deps /app/packages/inbox-crypto/node_modules ./packages/inbox-crypto/node_modules
# Copy source
COPY tsconfig.base.json tsconfig.json ./
COPY packages/inbox-crypto ./packages/inbox-crypto
COPY apps/inbox-backend ./apps/inbox-backend
# Generate Prisma client
RUN pnpm -F @firma-ec/inbox-backend prisma:generate
# Bundle backend (esbuild inlines @firma-ec/inbox-crypto source)
RUN pnpm -F @firma-ec/inbox-backend build

# ---------- runtime ----------
FROM node:22.23.4-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
# R2 + aws-sdk-s3 ≥1.196 flexible-checksums workaround (memoria workspace)
ENV AWS_REQUEST_CHECKSUM_CALCULATION=WHEN_REQUIRED
ENV PORT=3000
ENV HOST=0.0.0.0
RUN apk upgrade --no-cache ca-certificates && apk add --no-cache wget tini
# Bundle output
COPY --from=build /app/apps/inbox-backend/dist ./dist
# Prisma client + schema (needed at runtime for migrate deploy + queries)
COPY --from=build /app/apps/inbox-backend/prisma ./prisma
COPY --from=build /app/apps/inbox-backend/node_modules/@prisma ./node_modules/@prisma
COPY --from=build /app/apps/inbox-backend/node_modules/.prisma ./node_modules/.prisma
# Native deps externalised from the bundle (argon2 has prebuilds)
COPY --from=build /app/apps/inbox-backend/node_modules/argon2 ./node_modules/argon2
COPY --from=build /app/apps/inbox-backend/node_modules/@phc ./node_modules/@phc
COPY --from=build /app/apps/inbox-backend/node_modules/node-addon-api ./node_modules/node-addon-api
COPY --from=build /app/apps/inbox-backend/node_modules/node-gyp-build ./node_modules/node-gyp-build
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/healthz || exit 1
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/index.js"]
