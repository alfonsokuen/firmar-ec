# Build stage
# Node 22 to match CI (.github/workflows/*) and pwa.Dockerfile. The lockfile
# pulls undici@8.3.0 which requires Node >=22.19; node:20 fails the build.
FROM node:22-alpine AS build
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate
WORKDIR /app
COPY pnpm-workspace.yaml pnpm-lock.yaml package.json .npmrc ./
COPY apps/landing/package.json ./apps/landing/
COPY tsconfig.base.json ./
RUN pnpm install --frozen-lockfile --filter @firma-ec/landing...
COPY apps/landing ./apps/landing
# El `build` del paquete invoca este guardarraíl por ruta relativa (../../scripts):
# sin el COPY, el build falla con MODULE_NOT_FOUND dentro de la imagen. Se copia
# solo el script, no todo `scripts/` (que trae los deploy con hosts internos).
COPY scripts/check-wa-number.mjs ./scripts/
# `check-size-claims.mjs` valida las cifras de tamano publicadas contra las
# constantes REALES de la PWA, asi que necesita esos dos fuentes dentro de la
# imagen. Sin ellos el guard aborta el build (que es lo que hizo la primera vez
# — falla ruidoso, no silencioso). Se copian solo los dos ficheros que lee, no
# el workspace entero: el guard es la unica razon por la que la imagen de la
# landing conoce a la PWA, y conviene que ese acoplamiento sea explicito y minimo.
COPY apps/pwa/src/ui/Drop.svelte ./apps/pwa/src/ui/
COPY apps/pwa/src/lib/workers/sign-queue.ts ./apps/pwa/src/lib/workers/
# `check-announced-urls.mjs` cruza las URLs que el landing ANUNCIA contra las que
# la PWA sabe resolver, asi que necesita las dos tablas reales: los alias de path
# y la tabla de rutas del router. Se copian solo esos dos ficheros, por la misma
# razon que los dos de arriba: el acoplamiento landing->PWA queda explicito y
# minimo. Sin ellos el guard aborta el build con un mensaje que dice el arreglo.
COPY apps/pwa/src/lib/pathAlias.ts ./apps/pwa/src/lib/
COPY apps/pwa/src/App.svelte ./apps/pwa/src/
# `astro.config.mjs` inyecta en el JSON-LD la version REAL de la PWA leyendola
# de su package.json (`appVersionDefine()`), para que `softwareVersion` no sea
# un numero escrito a mano que se queda atras. Son los dos unicos ficheros que
# esa funcion toca: el helper y el package.json del que lee. Sin ellos el build
# muere aqui dentro con «Unable to load your Astro config» aunque pase en local
# — que es exactamente lo que paso al introducirlo (Landing CI en rojo).
COPY apps/pwa/appVersion.ts ./apps/pwa/
COPY apps/pwa/package.json ./apps/pwa/
# Número esperado por el guardarraíl; `off` desactiva su aserción positiva.
# Vacío NO desactiva: cae al default (fail-closed).
ARG WA_EXPECTED_NUMBER
ENV WA_EXPECTED_NUMBER=$WA_EXPECTED_NUMBER
# URL de la tienda de certificados para los CTA cruzados firma→tienda. Default = tienda
# pública; overridable por --build-arg (p.ej. apuntar a QA). Astro la inlina en build.
ARG PUBLIC_STORE_URL="https://tienda.firmar.ec"
ENV PUBLIC_STORE_URL=$PUBLIC_STORE_URL
RUN pnpm --filter @firma-ec/landing build

# Pre-compress assets for Caddy precompressed serving
RUN apk add --no-cache brotli gzip && \
    find apps/landing/dist -type f \( -name '*.html' -o -name '*.js' -o -name '*.css' -o -name '*.svg' -o -name '*.json' -o -name '*.txt' \) -exec sh -c 'brotli -q 11 "$1" -o "$1.br" && gzip -k -9 "$1"' _ {} \;

# Runtime stage — official Caddy on Alpine (chainguard caddy moved to paid tier 2026-Q1)
# Caddy compilado aqui con la toolchain de Go del builder oficial: no hay imagen oficial de
# Caddy con el Go parcheado (avisos de Go de oct-2026; caddy:2.11.7 trae Go 1.26.8). La guarda
# falla el build si el Go resultante no es >= 1.27.3 o >= 1.26.10, para que un builder viejo
# no vuelva a colar un binario vulnerable. Disparador para retirar esta etapa: cuando la imagen
# oficial caddy:2.x-alpine publique Go >= 1.27.3 / 1.26.10, volver a `FROM caddy:<version>-alpine`.
FROM caddy:2.11.7-builder AS caddy-build
RUN xcaddy build v2.11.7
RUN go_ver="$(/usr/bin/caddy build-info | awk '$1=="go"{print $2}')" && \
    echo "caddy compilado con $go_ver" && \
    printf '%s\n' "$go_ver" | grep -Eq '^go1\.(27\.([3-9]|[1-9][0-9])|(2[89]|[3-9][0-9])\.[0-9]+|26\.(1[0-9]|[2-9][0-9]))$' \
      || { echo "Go $go_ver sin los parches requeridos (>= 1.27.3 o >= 1.26.10)" >&2; exit 1; }

FROM caddy:2.11.7-alpine
COPY --from=caddy-build /usr/bin/caddy /usr/bin/caddy
RUN adduser -D -u 10001 -s /sbin/nologin nonroot
COPY --from=build /app/apps/landing/dist /srv
COPY infra/docker/Caddyfile.landing /etc/caddy/Caddyfile
# El Caddyfile real debe ser valido con el binario recien compilado: si no, falla el build y no el arranque.
RUN caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD wget --quiet --spider http://localhost:8080/ || exit 1
USER nonroot
