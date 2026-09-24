#!/usr/bin/env bash
# Despliega firma-ec-verify (API de verificacion PAdES) como STACK DEDICADO.
# Los stacks firma-ec (landing/pwa) y firma-ec-stats NO se tocan.
#
# Pre-requisitos (una sola vez):
#   scripts/provision-verify-secrets.sh   -> crea los dos Docker secrets
#   DNS + tunnel para api.firmar.ec       -> ver infra/cloudflare/tunnel.yml
#
# Uso:  scripts/deploy-verify-api.sh [version]   (default: apps/verify-api/package.json)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$REPO_ROOT"
VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  VERSION="$(grep '"version"' apps/verify-api/package.json | head -1 | sed -E 's/.*"version": "([^"]+)".*/\1/')"
fi
[[ -z "$VERSION" ]] && { echo "ERROR: no pude determinar la version"; exit 1; }

. "$REPO_ROOT/scripts/_deploy-guard.sh" # before the env file: see the bypass note there
. "$REPO_ROOT/scripts/_deploy-env.sh"
deploy_guard_on_main || exit 1
IMAGE="$REGISTRY/firma-ec-verify:$VERSION"
STACK_FILE="infra/compose/stack-firma-ec-verify.deploy.yml"
SERVICE="firma-ec-verify_verify"
TGZ="/tmp/firma-ec-verify-deploy-$VERSION.tgz"

echo "==> Desplegando firma-ec-verify $VERSION via root@$HOST  (image $IMAGE)"

# El guard comprobaba dos secrets, pero `firma_verify_api_keys` NO existe ni debe:
# el diseño dejó como secret SOLO el pepper, y movió la lista de claves a un
# fichero editable en NFS —añadir o revocar una clave no puede exigir recrear un
# secret inmutable de Swarm—. El guard nunca se actualizó, así que bloqueaba
# TODOS los despliegues pidiendo algo que el propio diseño elimino.
echo "==> [1/8] Pre-flight: pepper (secret) + lista de claves (fichero NFS)"
ssh root@"$HOST" 'set -e
  docker secret ls --format "{{.Name}}" | grep -qx firma_verify_api_pepper \
    || { echo "FALTA el secret firma_verify_api_pepper -> corre scripts/provision-verify-secrets.sh"; exit 1; }

  KEYS=/mnt/swarm-nfs/firma-ec-verify/api-keys.json
  [ -s "$KEYS" ] || { echo "FALTA o esta vacio $KEYS -> corre scripts/provision-verify-secrets.sh"; exit 1; }

  # Una lista corrupta o vacia no rompe el arranque de forma visible: deja un
  # servicio que responde 200 en /livez y 401 a TODO el mundo. Se comprueba aqui,
  # que es donde todavia se puede parar.
  n=$(node -e "const a=require(\"$KEYS\");if(!Array.isArray(a))throw 0;process.stdout.write(String(a.length))" 2>/dev/null) \
    || { echo "$KEYS no es un JSON valido"; exit 1; }
  [ "$n" -gt 0 ] || { echo "$KEYS no tiene ninguna clave: el servicio autenticaria a nadie"; exit 1; }
  echo "pre-flight OK (pepper + $n clave(s))"'

echo "==> [2/8] Tar del repo"
tar --exclude=node_modules --exclude=.git --exclude=dist --exclude=_backups \
    --exclude=_scratch --exclude=coverage --exclude=.astro \
    -czf "$TGZ" .
ls -lh "$TGZ"

echo "==> [3/8] SCP a $HOST"
scp "$TGZ" root@"$HOST":/root/firma-ec-verify-build.tgz

echo "==> [4/8] Extraer limpio en $HOST"
ssh root@"$HOST" "set -e; rm -rf /root/firma-ec-verify-build && mkdir -p /root/firma-ec-verify-build && cd /root/firma-ec-verify-build && tar xzf /root/firma-ec-verify-build.tgz && grep version apps/verify-api/package.json"

echo "==> [5/8] Docker build + push"
ssh root@"$HOST" "cd /root/firma-ec-verify-build && docker build -f apps/verify-api/Dockerfile -t $IMAGE . && docker push $IMAGE"

echo "==> [6/8] Stack deploy DEDICADO (firma-ec-verify)"
ssh root@"$HOST" "cd /root/firma-ec-verify-build && REGISTRY=$REGISTRY VERIFY_TAG=$VERSION docker stack deploy -c $STACK_FILE firma-ec-verify --with-registry-auth"

echo "==> [7/8] Esperar convergencia REAL"
# GOTCHA heredado del deploy de stats (costo: un despliegue dado por bueno a
# mitad del rollout): mirar solo '.Replicas' da FALSO VERDE, porque con
# order=stop-first la primera lectura devuelve el estado ANTERIOR. Hay que
# exigir UpdateStatus=completed Y que toda tarea corriendo lleve NUESTRA
# etiqueta.
UPD=""; REPL=""; TAGS=""
for i in $(seq 1 60); do
  UPD="$(ssh root@"$HOST" "docker service inspect $SERVICE --format '{{.UpdateStatus.State}}'" 2>/dev/null || true)"
  TAGS="$(ssh root@"$HOST" "docker service ps $SERVICE --filter desired-state=running --format '{{.Image}}'" 2>/dev/null | sed 's#.*firma-ec-verify:##; s#@.*##' | sort -u | tr '\n' ' ' | sed 's/ $//')"
  REPL="$(ssh root@"$HOST" "docker service ls --filter name=$SERVICE --format '{{.Replicas}}'" || true)"
  echo "  update=${UPD:-<none>}  replicas=${REPL:-<none>}  tags=[${TAGS:-<none>}] (intento $i/60)"
  case "$UPD" in
    rollback_completed|rollback_paused)
      echo "ERROR: Swarm revirtio el despliegue (failure_action=rollback). La imagen $VERSION no arranca."
      ssh root@"$HOST" "docker service ps $SERVICE --no-trunc | head -20" || true
      exit 1
      ;;
    paused)
      echo "ERROR: el despliegue quedo en pausa."
      ssh root@"$HOST" "docker service ps $SERVICE --no-trunc | head -20" || true
      exit 1
      ;;
  esac
  # Nota: el servicio corre con UNA replica a proposito (cuota e idempotencia
  # son por proceso), asi que el objetivo es 1/1, no 2/2.
  if [[ "$UPD" == "completed" || "$UPD" == "" ]] && [[ "$REPL" == 1/1* ]] && [[ "$TAGS" == "$VERSION" ]]; then
    break
  fi
  sleep 5
done
if [[ "$REPL" != 1/1* || "$TAGS" != "$VERSION" ]]; then
  echo "ERROR: el servicio no convergio a $VERSION (update=$UPD replicas=$REPL tags=[$TAGS])"
  ssh root@"$HOST" "docker service ps $SERVICE --no-trunc | head -20" || true
  exit 1
fi
echo "  convergido: 1/1 tarea en $VERSION"

echo "==> [8/8] Smoke de ORIGEN (bypass Cloudflare via --resolve a Traefik)"

# 8a. Liveness.
OK=0
for i in $(seq 1 15); do
  CODE="$(curl -sk -o /dev/null -w '%{http_code}' --resolve api.firmar.ec:443:"$HOST" "https://api.firmar.ec/livez" || echo 000)"
  echo "  /livez -> HTTP $CODE (intento $i/15)"
  [[ "$CODE" == "200" ]] && { OK=1; break; }
  sleep 2
done
[[ "$OK" == "1" ]] || { echo "ERROR: /livez no dio 200"; exit 1; }

# 8b. Readiness REAL: las anclas de confianza tienen que estar TODAS usables.
#     Un subconjunto produce "no confiable" para firmas legitimas, que es el
#     fallo que mas duele porque se parece a un documento adulterado.
BODY="$(curl -sk --resolve api.firmar.ec:443:"$HOST" "https://api.firmar.ec/healthz" || true)"
echo "  /healthz -> $BODY"
echo "$BODY" | grep -q '"status":"ok"' || { echo "ERROR: /healthz no esta ok"; exit 1; }
USABLE="$(echo "$BODY" | sed -E 's/.*"usableAnchors":([0-9]+).*/\1/')"
DECLARED="$(echo "$BODY" | sed -E 's/.*"declaredAnchors":([0-9]+).*/\1/')"
[[ "$USABLE" == "$DECLARED" && "$USABLE" -gt 0 ]] || {
  echo "ERROR: anclas de confianza degradadas ($USABLE/$DECLARED)"; exit 1; }
echo "  anclas: $USABLE/$DECLARED usables"

# 8c. La API tiene que EXIGIR clave. Un 200 aqui seria un fallo de seguridad.
CODE="$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/pdf' \
  --data-binary '%PDF-1.7 no soy un documento' \
  --resolve api.firmar.ec:443:"$HOST" "https://api.firmar.ec/v1/verify" || echo 000)"
echo "  POST /v1/verify sin clave -> HTTP $CODE"
[[ "$CODE" == "401" ]] || { echo "ERROR: la API respondio $CODE sin clave; deberia ser 401"; exit 1; }

echo "==> LISTO. firma-ec-verify $VERSION arriba y validado en ORIGEN."
echo "    Verificacion end-to-end con una clave real: ver docs/verify-api-pilot.md"
rm -f "$TGZ"
