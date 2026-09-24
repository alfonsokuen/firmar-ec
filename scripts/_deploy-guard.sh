# shellcheck shell=bash
# _deploy-guard.sh — a manual deploy may only ship what the CI would ship.
#
# Why (2026-09-24): the landing went live as 0.7.9-utm-ad4ff5a from GitHub
# main (PRs #2 and #3) while Gitea main — the branch the CI deploys — stayed
# 10 commits behind. Production ran code no CI branch had, and the next push
# to Gitea main would have silently reverted it. GitHub is only a push-mirror
# of Gitea; the source is gitea/main.
#
# Guard: the commit being deployed must be the TIP of gitea/main (the CI would
# ship exactly that; an older main commit would roll production back) and the
# working tree must be clean (the deploy scripts tar the directory as is, so
# uncommitted changes would ship too). Remote and branch are fixed on purpose:
# pointing the guard at a mirror is how the drift happened.
#
# Emergency bypass: ALLOW_OFF_MAIN_DEPLOY=1 on the command line, never
# persisted — a bypass left in .deploy.env would silently disable the guard
# for every later deploy, so that is refused. The bypass is loud.
#
# Usage: source this file BEFORE _deploy-env.sh, call deploy_guard_on_main after it.

readonly DEPLOY_GUARD_REMOTE=gitea
readonly DEPLOY_GUARD_BRANCH=main
# Captured when this file is sourced, i.e. BEFORE _deploy-env.sh loads
# .deploy.env: whatever that file sets or exports (in any bash syntax) can no
# longer turn the bypass on. Readonly, so it cannot be reassigned either.
readonly _DEPLOY_GUARD_BYPASS="${ALLOW_OFF_MAIN_DEPLOY:-}"

deploy_guard_on_main() {
  local ref="$DEPLOY_GUARD_REMOTE/$DEPLOY_GUARD_BRANCH"
  local root head tip bypass=0
  root="$(git rev-parse --show-toplevel)" || return 1
  head="$(git rev-parse HEAD)" || return 1

  if [[ -f "$root/.deploy.env" ]] && grep -Eq '^[[:space:]]*(export[[:space:]]+)?ALLOW_OFF_MAIN_DEPLOY=' "$root/.deploy.env"; then
    echo "RECHAZADO: ALLOW_OFF_MAIN_DEPLOY esta fijado en .deploy.env; la excepcion va solo en la linea de comandos." >&2
    return 1
  fi
  [[ "$_DEPLOY_GUARD_BYPASS" == "1" ]] && bypass=1

  if [[ -n "$(git status --porcelain)" ]]; then
    if [[ "$bypass" == 1 ]]; then
      echo "AVISO: ALLOW_OFF_MAIN_DEPLOY=1 — se despliega un arbol con cambios sin commitear." >&2
    else
      echo "RECHAZADO: el arbol de trabajo tiene cambios sin commitear; el deploy los empaquetaria." >&2
      return 1
    fi
  fi

  if ! git fetch -q "$DEPLOY_GUARD_REMOTE" "$DEPLOY_GUARD_BRANCH"; then
    echo "RECHAZADO: no se pudo leer $ref para comprobar que $head es su punta." >&2
    return 1
  fi
  tip="$(git rev-parse "$ref")" || return 1
  if [[ "$head" == "$tip" ]]; then
    return 0
  fi
  if [[ "$bypass" == 1 ]]; then
    echo "AVISO: ALLOW_OFF_MAIN_DEPLOY=1 — se despliega $head, que NO es la punta de $ref ($tip)." >&2
    echo "       Integralo en $ref cuanto antes: el proximo deploy del CI lo revertiria." >&2
    return 0
  fi
  echo "RECHAZADO: $head no es la punta de $ref ($tip). El CI despliega esa punta:" >&2
  echo "           integra el cambio en main, o solo en emergencia repite con ALLOW_OFF_MAIN_DEPLOY=1." >&2
  return 1
}
# The env file is sourced after this one: it must not be able to replace the check.
readonly -f deploy_guard_on_main
