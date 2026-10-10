FROM node:24-bookworm-slim AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY package*.json tsconfig.base.json ./
COPY apps/api/package.json apps/api/
COPY apps/web/package.json apps/web/
COPY packages/shared-types/package.json packages/shared-types/
COPY packages/detection-rules/package.json packages/detection-rules/
RUN npm ci --no-audit --no-fund
COPY apps/api apps/api
COPY packages packages
COPY scripts scripts
RUN npm run db:generate && npm run build --workspace @zeroeye/api
FROM build AS migrate
CMD ["npm","run","db:migrate"]
FROM build AS runtime
RUN npm prune --omit=dev --ignore-scripts
ENV NODE_ENV=production HOST=0.0.0.0 PORT=4000
USER node
EXPOSE 4000
CMD ["node","apps/api/dist/apps/api/src/index.js"]
