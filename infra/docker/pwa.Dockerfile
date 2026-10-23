FROM node:22-alpine AS build
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate
WORKDIR /app
# Copy workspace metadata first (cache layer)
COPY pnpm-workspace.yaml pnpm-lock.yaml package.json .npmrc ./
COPY tsconfig.base.json ./
COPY apps/pwa/package.json ./apps/pwa/
COPY packages/tsl-ec/package.json ./packages/tsl-ec/
COPY packages/verifier/package.json ./packages/verifier/
COPY packages/crypto-core/package.json ./packages/crypto-core/
COPY packages/pdf-sign/package.json ./packages/pdf-sign/
COPY packages/ui-kit/package.json ./packages/ui-kit/
COPY packages/signer/package.json ./packages/signer/
COPY packages/tsa-client/package.json ./packages/tsa-client/
COPY packages/tsa-trust/package.json ./packages/tsa-trust/
COPY packages/inbox-crypto/package.json ./packages/inbox-crypto/
COPY packages/ltv-validation/package.json ./packages/ltv-validation/
COPY packages/dss-pdf/package.json ./packages/dss-pdf/
RUN pnpm install --frozen-lockfile --filter @firma-ec/pwa...
# Copy source
COPY apps/pwa ./apps/pwa
COPY packages ./packages
# El `build` del paquete invoca este guardarraíl por ruta relativa (../../scripts):
# sin el COPY, el build falla con MODULE_NOT_FOUND dentro de la imagen. Se copia
# solo el script, no todo `scripts/` (que trae los deploy con hosts internos).
COPY scripts/check-wa-number.mjs ./scripts/
# Idem para el guardarrail de version: el `build` de la PWA lo invoca detras del
# anterior, asi que olvidarlo rompe el build entero (paso: 0.22.6 no llego a construir).
COPY scripts/check-app-version.mjs ./scripts/
# Número esperado por el guardarraíl; `off` desactiva su aserción positiva.
# Vacío NO desactiva: cae al default (fail-closed).
ARG WA_EXPECTED_NUMBER
ENV WA_EXPECTED_NUMBER=$WA_EXPECTED_NUMBER
# Handoff opt-in allow-list. Vacío por defecto = handoff DESHABILITADO (fail-closed): el
# código y la imagen publicada quedan tenant-neutros (AGPL). El OPERADOR que despliega su
# instancia lo setea por --build-arg (config de deploy, no en el source).
ARG VITE_HANDOFF_ALLOWLIST=""
ENV VITE_HANDOFF_ALLOWLIST=$VITE_HANDOFF_ALLOWLIST
# Canonical app URL for handoff instances. Vacío por defecto = sin redirect (el
# público app.firmar.ec no se toca). El OPERADOR de una instancia dedicada de
# handoff lo setea por --build-arg para que toda visita que NO sea el flujo de
# firma rebote a la app real (así lo único instalable es el firmar.ec real).
ARG VITE_REDIRECT_HOME=""
ENV VITE_REDIRECT_HOME=$VITE_REDIRECT_HOME
# URL de la tienda de certificados para el CTA "renovar/comprar" (cross-sell firma→tienda).
# Default = tienda pública; overridable por --build-arg. Vite la inlina en build.
ARG VITE_STORE_URL="https://tienda.firmar.ec"
ENV VITE_STORE_URL=$VITE_STORE_URL
# Línea de WhatsApp de cara al cliente (ayuda del modo guiado, ayuda de certificado,
# patrocinio). Vacío = el default de `apps/pwa/src/lib/links.ts` (instancia `firmarec`).
# Sin este ARG el override NO llega al build: Vite lee import.meta.env en build-time,
# así que setear la env en el servicio no cambia nada (era el bug del 2026-07-29).
ARG VITE_WHATSAPP_URL=""
ENV VITE_WHATSAPP_URL=$VITE_WHATSAPP_URL
RUN pnpm --filter @firma-ec/pwa build

RUN apk add --no-cache brotli gzip && \
    find apps/pwa/dist -type f \( -name '*.html' -o -name '*.js' -o -name '*.css' -o -name '*.svg' -o -name '*.json' -o -name '*.webmanifest' \) -exec sh -c 'brotli -q 11 "$1" -o "$1.br" && gzip -k -9 "$1"' _ {} \;

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
COPY --from=build /app/apps/pwa/dist /srv
COPY infra/docker/Caddyfile.pwa /etc/caddy/Caddyfile
# El Caddyfile real debe ser valido con el binario recien compilado: si no, falla el build y no el arranque.
RUN caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD wget --quiet --spider http://localhost:8080/ || exit 1
USER nonroot
