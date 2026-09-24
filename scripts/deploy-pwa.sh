#!/usr/bin/env bash
# Deploy pwa to firmar.ec via IDK Swarm.
#
# Usage:
#   scripts/deploy-pwa.sh [version]
#
# Reads apps/pwa/package.json version if no argument is given.
# Requires SSH access to root@<SWARM-MANAGER> (IASERVER01 — Swarm manager + registry host).
#
# Pipeline:
#   1. Verify version coherence (package.json vs tag)
#   2. Tar repo (excluding node_modules, dist, _backups, _scratch, .git)
#   3. SCP to IAS01 :/root/firma-ec-build/
#   4. docker build -f infra/docker/pwa.Dockerfile
#   5. docker push to <REGISTRY>
#   6. docker service update --update-order start-first --force
#   7. HTTP smoke verify

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  VERSION="$(grep '"version"' apps/pwa/package.json | head -1 | sed -E 's/.*"version": "([^"]+)".*/\1/')"
fi
[[ -z "$VERSION" ]] && { echo "ERROR: cannot determine version"; exit 1; }

. "$REPO_ROOT/scripts/_deploy-guard.sh"
deploy_guard_on_main || exit 1 # before the env file is sourced: nothing in it can reach the check
. "$REPO_ROOT/scripts/_deploy-env.sh"
IMAGE="$REGISTRY/firma-ec-pwa:$VERSION"
TGZ="/tmp/firma-ec-pwa-deploy-$VERSION.tgz"

echo "==> Deploying firma-ec-pwa $VERSION via root@$HOST"
echo "==> Image: $IMAGE"

echo "==> [1/6] Tar repo"
tar --exclude=node_modules --exclude=.git --exclude=dist --exclude=_backups \
    --exclude=_scratch --exclude=coverage --exclude=.astro \
    -czf "$TGZ" .
ls -lh "$TGZ"

echo "==> [2/6] SCP to $HOST"
scp "$TGZ" root@$HOST:/root/firma-ec-build.tgz

echo "==> [3/6] Extract on $HOST"
ssh root@$HOST "set -e; mkdir -p /root/firma-ec-build && cd /root/firma-ec-build && tar xzf /root/firma-ec-build.tgz && grep version apps/pwa/package.json"

echo "==> [4/6] Docker build $IMAGE"
ssh root@$HOST "cd /root/firma-ec-build && docker build --build-arg VITE_HANDOFF_ALLOWLIST='${VITE_HANDOFF_ALLOWLIST:-}' --build-arg VITE_STORE_URL='${VITE_STORE_URL:-https://tienda.firmar.ec}' --build-arg VITE_WHATSAPP_URL='${VITE_WHATSAPP_URL:-}' -f infra/docker/pwa.Dockerfile -t $IMAGE ."

echo "==> [5/6] Docker push"
ssh root@$HOST "docker push $IMAGE"

echo "==> [6/6] Swarm update firma-ec_pwa"
ssh root@$HOST "docker service update --image $IMAGE --update-order start-first --force firma-ec_pwa"

echo "==> Smoke verify"
sleep 5

# El smoke solo miraba %{http_code}, y este sitio sirve un catch-all SPA: una
# ruta de asset que NO existe devuelve 200 con `text/html` (el index). Es decir,
# el verificador de despliegue habria pasado en VERDE con el bug del 2026-08-23
# presente —el worker de PDF.js servido como HTML, que mataba la firma en 22
# escenarios e2e—. Por eso los assets criticos se afirman por CONTENT-TYPE, no
# por codigo, y el propio catch-all se prueba en rojo al final.
SMOKE_HOST="${SMOKE_HOST:-https://app.firmar.ec}"
smoke_failed=0

check_path() {  # $1 = ruta, $2 = patron de content-type esperado (vacio = solo 200)
  local path="$1" want="$2" code ctype
  read -r code ctype <<<"$(curl -sS -o /dev/null -w '%{http_code} %{content_type}' "$SMOKE_HOST/$path" || echo 'FAIL -')"
  if [[ "$code" != "200" ]]; then
    echo "  $path -> $code  [FALLO: se esperaba 200]"
    smoke_failed=1
    return
  fi
  if [[ -n "$want" && "$ctype" != *"$want"* ]]; then
    echo "  $path -> $code $ctype  [FALLO: se esperaba content-type $want]"
    smoke_failed=1
    return
  fi
  echo "  $path -> $code ${ctype:-(sin tipo)}"
}

# Paginas: basta el 200.
for path in / manifest.webmanifest; do check_path "$path" ""; done
# Assets criticos: el TIPO es la afirmacion. Si el catch-all los cubre, aqui se ve.
check_path "trust/tsl-ec.json" "json"
check_path "pdfjs/pdf.worker.min.mjs" "javascript"
# Nombre real del paquete pdfjs-dist (no hay FoxitSans: la sans es
# LiberationSans-*.ttf). Si se sube de major, verificar que sigue existiendo.
check_path "pdfjs/standard_fonts/FoxitSerif.pfb" "octet-stream"

# Control negativo: una ruta que NO existe DEBE ser servida por el catch-all
# como HTML. Si un dia devuelve otra cosa, la premisa de los checks de arriba
# cambio y hay que revisarlos (esto es lo que hace que el verde de arriba
# signifique algo).
neg_ctype=$(curl -sS -o /dev/null -w '%{content_type}' "$SMOKE_HOST/pdfjs/__no-existe-$RANDOM.mjs" || echo '-')
if [[ "$neg_ctype" != *"html"* ]]; then
  echo "  [AVISO] el control negativo devolvio '$neg_ctype', no HTML: revisar la premisa del smoke"
else
  echo "  control negativo OK (ruta inexistente -> $neg_ctype, por eso se afirma el tipo)"
fi

if [[ "$smoke_failed" != "0" ]]; then
  echo "SMOKE EN ROJO — el despliegue quedo servido pero NO verificado." >&2
  echo "Rollback: docker service update --image <imagen-anterior> --update-order start-first firma-ec_pwa" >&2
  exit 1
fi

echo "==> DONE. Cleanup local tar:"
rm -f "$TGZ"
echo "OK."
