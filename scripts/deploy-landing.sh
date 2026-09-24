#!/usr/bin/env bash
# Deploy landing to firmar.ec via IDK Swarm.
#
# Usage:
#   scripts/deploy-landing.sh [version]
#
# Reads apps/landing/package.json version if no argument is given.
# Requires SSH access to root@<SWARM-MANAGER> (IASERVER01 — Swarm manager + registry host).
#
# Pipeline:
#   1. Verify version coherence (package.json vs tag)
#   2. Tar repo (excluding node_modules, dist, _backups, _scratch, .git)
#   3. SCP to IAS01 :/root/firma-ec-build/
#   4. docker build -f infra/docker/landing.Dockerfile
#   5. docker push to <REGISTRY>
#   6. docker service update --update-order start-first --force
#   7. HTTP smoke verify

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  VERSION="$(grep '"version"' apps/landing/package.json | head -1 | sed -E 's/.*"version": "([^"]+)".*/\1/')"
fi
[[ -z "$VERSION" ]] && { echo "ERROR: cannot determine version"; exit 1; }

. "$REPO_ROOT/scripts/_deploy-guard.sh"
deploy_guard_on_main || exit 1 # before the env file is sourced: nothing in it can reach the check
. "$REPO_ROOT/scripts/_deploy-env.sh"
IMAGE="$REGISTRY/firma-ec-landing:$VERSION"
TGZ="/tmp/firma-ec-landing-deploy-$VERSION.tgz"

echo "==> Deploying firma-ec-landing $VERSION via root@$HOST"
echo "==> Image: $IMAGE"

echo "==> [1/6] Tar repo"
tar --exclude=node_modules --exclude=.git --exclude=dist --exclude=_backups \
    --exclude=_scratch --exclude=coverage --exclude=.astro \
    -czf "$TGZ" .
ls -lh "$TGZ"

echo "==> [2/6] SCP to $HOST"
scp "$TGZ" root@$HOST:/root/firma-ec-build.tgz

echo "==> [3/6] Extract on $HOST (clean dir first — tar xzf does NOT delete files
#            absent from the archive; a stale public/sitemap.xml survived a deploy
#            this way 2026-05-23 and kept being served. Always extract fresh.)"
ssh root@$HOST "set -e; rm -rf /root/firma-ec-build && mkdir -p /root/firma-ec-build && cd /root/firma-ec-build && tar xzf /root/firma-ec-build.tgz && grep version apps/landing/package.json"

echo "==> [4/6] Docker build $IMAGE"
ssh root@$HOST "cd /root/firma-ec-build && docker build --build-arg PUBLIC_STORE_URL='${PUBLIC_STORE_URL:-https://tienda.firmar.ec}' -f infra/docker/landing.Dockerfile -t $IMAGE ."

echo "==> [5/6] Docker push"
ssh root@$HOST "docker push $IMAGE"

echo "==> [6/6] Swarm update firma-ec_landing"
ssh root@$HOST "docker service update --image $IMAGE --update-order start-first --force firma-ec_landing"

echo "==> Smoke verify"
sleep 5
for path in llms.txt llms-full.txt .well-known/ai-plugin.json; do
  code=$(curl -fsS -o /dev/null -w "%{http_code}" "https://firmar.ec/$path" || echo "FAIL")
  echo "  https://firmar.ec/$path → $code"
done

echo "==> DONE. Cleanup local tar:"
rm -f "$TGZ"
echo "OK."
