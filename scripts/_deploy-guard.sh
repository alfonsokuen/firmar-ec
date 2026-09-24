# shellcheck shell=bash
# _deploy-guard.sh — a manual deploy may only ship what the CI would ship.
#
# Why (2026-09-24): the landing went live as 0.7.9-utm-ad4ff5a from GitHub
# main (PRs #2 and #3) while Gitea main — the branch the CI deploys — stayed
# 10 commits behind. Production ran code no CI branch had, and the next push
# to Gitea main would have silently reverted it. The same day a security
# release had to go out by hand for the same reason, widening the gap.
#
# Guard: the commit being deployed must already be on <remote>/main and the
# working tree must be clean (the deploy scripts tar the directory as is, so
# uncommitted changes would ship too). An emergency bypass is explicit and
# loud: ALLOW_OFF_MAIN_DEPLOY=1 prints what is being shipped off main.
#
# Usage (sourced after _deploy-env.sh):  deploy_guard_on_main
# Env: DEPLOY_SOURCE_REMOTE (default gitea), DEPLOY_SOURCE_BRANCH (default main)

deploy_guard_on_main() {
  local remote="${DEPLOY_SOURCE_REMOTE:-gitea}" branch="${DEPLOY_SOURCE_BRANCH:-main}"
  local head
  head="$(git rev-parse HEAD)" || return 1

  if [[ -n "$(git status --porcelain)" ]]; then
    if [[ "${ALLOW_OFF_MAIN_DEPLOY:-}" == "1" ]]; then
      echo "AVISO: ALLOW_OFF_MAIN_DEPLOY=1 — se despliega un arbol con cambios sin commitear." >&2
    else
      echo "RECHAZADO: el arbol de trabajo tiene cambios sin commitear; el deploy los empaquetaria." >&2
      return 1
    fi
  fi

  if ! git fetch -q "$remote" "$branch"; then
    echo "RECHAZADO: no se pudo leer $remote/$branch para comprobar que $head esta en main." >&2
    return 1
  fi
  if git merge-base --is-ancestor "$head" "$remote/$branch"; then
    return 0
  fi
  if [[ "${ALLOW_OFF_MAIN_DEPLOY:-}" == "1" ]]; then
    echo "AVISO: ALLOW_OFF_MAIN_DEPLOY=1 — se despliega $head, que NO esta en $remote/$branch." >&2
    echo "       Integralo en $remote/$branch cuanto antes: el proximo deploy del CI lo revertiria." >&2
    return 0
  fi
  echo "RECHAZADO: $head no esta en $remote/$branch. Integralo en main (el CI despliega desde ahi)" >&2
  echo "           o, solo en emergencia, repite con ALLOW_OFF_MAIN_DEPLOY=1." >&2
  return 1
}
