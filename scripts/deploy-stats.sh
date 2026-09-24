#!/usr/bin/env bash
# Despliega firma-ec-stats (backend de usage-stats) como STACK DEDICADO
# `firma-ec-stats` — totalmente separado del stack firma-ec (landing/pwa), que NO
# se toca. Levanta el servicio SIN cortar trafico publico: el CF Worker sigue
# duenno de /api/stats* en el edge hasta que corras scripts/cutover-stats.sh.
#
# Pre-requisito: scripts/provision-stats-db.sh ya corrio (DB firmar_ec_stats +
# Docker secrets firma_stats_database_url / firma_stats_redis_url) Y el esquema
# fue migrado (paso 5 de provision).
#
# Uso:  scripts/deploy-stats.sh [version]   (default: apps/stats-backend/package.json)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$REPO_ROOT"
VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  VERSION="$(grep '"version"' apps/stats-backend/package.json | head -1 | sed -E 's/.*"version": "([^"]+)".*/\1/')"
fi
[[ -z "$VERSION" ]] && { echo "ERROR: no pude determinar la version"; exit 1; }

. "$REPO_ROOT/scripts/_deploy-guard.sh"
deploy_guard_on_main || exit 1 # before the env file is sourced: nothing in it can reach the check
. "$REPO_ROOT/scripts/_deploy-env.sh"
IMAGE="$REGISTRY/firma-ec-stats:$VERSION"
STACK_FILE="infra/compose/stack-firma-ec-stats.deploy.yml"
TGZ="/tmp/firma-ec-stats-deploy-$VERSION.tgz"

echo "==> Desplegando firma-ec-stats $VERSION via root@$HOST  (image $IMAGE)"

echo "==> [1/7] Pre-flight: los Docker secrets deben existir"
ssh root@"$HOST" 'for s in firma_stats_database_url firma_stats_redis_url; do
  docker secret ls --format "{{.Name}}" | grep -qx "$s" || { echo "FALTA secret $s -> corre scripts/provision-stats-db.sh primero"; exit 1; }
done; echo "secrets OK"'

echo "==> [2/7] Tar del repo"
tar --exclude=node_modules --exclude=.git --exclude=dist --exclude=_backups \
    --exclude=_scratch --exclude=coverage --exclude=.astro \
    -czf "$TGZ" .
ls -lh "$TGZ"

echo "==> [3/7] SCP a $HOST"
scp "$TGZ" root@"$HOST":/root/firma-ec-stats-build.tgz

echo "==> [4/7] Extraer limpio en $HOST"
ssh root@"$HOST" "set -e; rm -rf /root/firma-ec-stats-build && mkdir -p /root/firma-ec-stats-build && cd /root/firma-ec-stats-build && tar xzf /root/firma-ec-stats-build.tgz && grep version apps/stats-backend/package.json"

echo "==> [5/7] Docker build + push"
ssh root@"$HOST" "cd /root/firma-ec-stats-build && docker build -f apps/stats-backend/Dockerfile -t $IMAGE . && docker push $IMAGE"

echo "==> [6/7] Stack deploy DEDICADO (firma-ec-stats) — landing/pwa NO se tocan"
ssh root@"$HOST" "cd /root/firma-ec-stats-build && REGISTRY=$REGISTRY STATS_TAG=$VERSION docker stack deploy -c $STACK_FILE firma-ec-stats --with-registry-auth"

echo "==> [7/7] Esperar readiness REAL + smoke de ORIGEN BLOQUEANTE (worker aun sirve el publico)"
# GOTCHA (2026-08-24, costo: un despliegue dado por bueno a mitad del rollout):
# mirar solo '.Replicas' da FALSO VERDE. Con update_config.order=stop-first el
# rollout tarda un instante en arrancar, asi que la primera lectura devuelve el
# "2/2" del estado ANTERIOR y el script cerraba con la mitad del servicio aun
# en la imagen vieja. Hay que esperar a que Swarm declare el update terminado
# Y comprobar que TODA tarea corriendo lleva la etiqueta que acabamos de subir.
UPD=""
for i in $(seq 1 60); do
  UPD="$(ssh root@"$HOST" "docker service inspect firma-ec-stats_stats --format '{{.UpdateStatus.State}}'" 2>/dev/null || true)"
  # Imagenes distintas entre las tareas en ejecucion (sin el sufijo @sha256).
  TAGS="$(ssh root@"$HOST" "docker service ps firma-ec-stats_stats --filter desired-state=running --format '{{.Image}}'" 2>/dev/null | sed 's#.*firma-ec-stats:##; s#@.*##' | sort -u | tr '
' ' ' | sed 's/ $//')"
  REPL="$(ssh root@"$HOST" "docker service ls --filter name=firma-ec-stats_stats --format '{{.Replicas}}'" || true)"
  echo "  update=${UPD:-<none>}  replicas=${REPL:-<none>}  tags=[${TAGS:-<none>}] (intento $i/60)"
  case "$UPD" in
    rollback_completed|rollback_paused)
      echo "ERROR: Swarm revirtio el despliegue (failure_action=rollback). La imagen $VERSION no arranca."
      ssh root@"$HOST" "docker service ps firma-ec-stats_stats --no-trunc | head -20" || true
      exit 1
      ;;
    paused)
      echo "ERROR: el despliegue quedo en pausa."
      ssh root@"$HOST" "docker service ps firma-ec-stats_stats --no-trunc | head -20" || true
      exit 1
      ;;
  esac
  # Verde solo si: update completado, replicas al completo y UNA sola etiqueta,
  # la nuestra. Cualquier otra combinacion sigue esperando.
  if [[ "$UPD" == "completed" && "$REPL" == 2/2* && "$TAGS" == "$VERSION" ]]; then
    break
  fi
  sleep 5
done
if [[ "$UPD" != "completed" || "$REPL" != 2/2* || "$TAGS" != "$VERSION" ]]; then
  echo "ERROR: el servicio no convergio a $VERSION (update=$UPD replicas=$REPL tags=[$TAGS])"
  ssh root@"$HOST" "docker service ps firma-ec-stats_stats --no-trunc | head -20" || true
  exit 1
fi
echo "  convergido: 2/2 tareas en $VERSION, update completed"

echo "-- smoke de origen GET /api/stats (bypass CF via --resolve a Traefik) --"
OK=0
for i in $(seq 1 15); do
  CODE="$(curl -sk -o /tmp/stats-smoke.json -w '%{http_code}' --resolve firmar.ec:443:"$HOST" "https://firmar.ec/api/stats" || echo 000)"
  echo "  HTTP $CODE (intento $i/15)"
  [[ "$CODE" == "200" ]] && { OK=1; break; }
  sleep 2
done
[[ "$OK" == "1" ]] || { echo "ERROR: smoke de origen /api/stats no dio 200"; exit 1; }
echo "  body: $(cat /tmp/stats-smoke.json)"

echo "-- smoke GET /api/stats/series?granularity=day --"
OK2=0
for i in $(seq 1 15); do
  CODE="$(curl -sk -o /dev/null -w '%{http_code}' --resolve firmar.ec:443:"$HOST" "https://firmar.ec/api/stats/series?granularity=day" || echo 000)"
  echo "  HTTP $CODE (intento $i/15)"
  [[ "$CODE" == "200" ]] && { OK2=1; break; }
  sleep 2
done
[[ "$OK2" == "1" ]] || { echo "ERROR: /api/stats/series no dio 200"; exit 1; }

echo "==> LISTO. Servicio arriba y validado en ORIGEN. NO sirve trafico publico todavia."
echo "    Siguiente: scripts/cutover-stats.sh (seed + quitar rutas del Worker)."
rm -f "$TGZ"
