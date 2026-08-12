# Multi-stage: build with dev deps, ship without them.
FROM node:20-slim AS build
WORKDIR /app
# better-sqlite3 and sodium builds need a toolchain; it does not ship.
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:20-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV WITNESS_DB=/data/witness.db
ENV WITNESS_KEY=/data/witness-signing.key
ENV PORT=8080
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/package.json ./package.json

# Unprivileged. The volume is chowned by the start command because Fly mounts
# it as root and this container must not run as root to write to it.
RUN useradd --system --uid 10001 witness
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8080/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["sh", "-c", "mkdir -p /data && chown -R witness:witness /data && exec su witness -s /bin/sh -c 'node dist/index.js'"]
