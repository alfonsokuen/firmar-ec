# syntax=docker/dockerfile:1.7
# firmar.ec verify-api — PAdES verification API.
#
# The runtime image carries NO node_modules: esbuild bundles everything,
# including pino, so it is just Node plus two .js files. Verified before
# adopting it — the bundle boots, loads all 28 trust anchors and verifies a real
# signature with an empty node_modules.
#
# NOTE on the build stage: do NOT try to carry `node_modules` over from a
# separate deps stage. In a pnpm workspace every package has its OWN
# node_modules full of symlinks (asn1js, pkijs, the @firma-ec/* siblings), and
# copying only the root and app trees leaves the engine packages unresolvable —
# the first build failed with a wall of "Could not resolve @firma-ec/crypto-core".
# Installing in the same stage that holds the sources keeps the link farm intact.

FROM node:22.23.4-alpine AS build
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate
WORKDIR /app

# Manifests first, so the install layer is cached until a dependency changes.
# .npmrc is REQUIRED: it carries auto-install-peers=false, which must match the
# lockfile or --frozen-lockfile aborts with ERR_PNPM_LOCKFILE_CONFIG_MISMATCH.
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml .npmrc ./
COPY apps/verify-api/package.json apps/verify-api/
COPY apps/pwa/package.json apps/pwa/
COPY apps/landing/package.json apps/landing/
COPY apps/stats-backend/package.json apps/stats-backend/
COPY apps/inbox-backend/package.json apps/inbox-backend/
COPY packages/verifier/package.json packages/verifier/
COPY packages/crypto-core/package.json packages/crypto-core/
COPY packages/tsl-ec/package.json packages/tsl-ec/
COPY packages/tsa-trust/package.json packages/tsa-trust/
COPY packages/tsa-client/package.json packages/tsa-client/
COPY packages/ltv-validation/package.json packages/ltv-validation/
COPY packages/dss-pdf/package.json packages/dss-pdf/
COPY packages/signer/package.json packages/signer/
COPY packages/pdf-sign/package.json packages/pdf-sign/
COPY packages/inbox-crypto/package.json packages/inbox-crypto/
COPY packages/signare-client/package.json packages/signare-client/
COPY packages/ui-kit/package.json packages/ui-kit/
COPY packages/uanataca-client/package.json packages/uanataca-client/
RUN pnpm install --frozen-lockfile --ignore-scripts

# Sources afterwards. The build context excludes node_modules, so these COPYs
# add code without disturbing the freshly installed link farm.
COPY tsconfig.base.json tsconfig.json ./
COPY packages ./packages
COPY apps/verify-api ./apps/verify-api
RUN pnpm -F @firma-ec/verify-api build

# ---------- runtime ----------
FROM node:22.23.4-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000
ENV HOST=0.0.0.0
RUN apk upgrade --no-cache ca-certificates && apk add --no-cache wget tini
# Marks the bundle as ESM. Without it Node re-parses each file after failing to
# read it as CommonJS and warns on every boot.
RUN printf '{"type":"module"}' > /app/package.json
COPY --from=build /app/apps/verify-api/dist ./dist
USER node
EXPOSE 3000
# tini reaps the worker threads on shutdown.
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/index.js"]
