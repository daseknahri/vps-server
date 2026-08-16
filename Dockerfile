# License server for Za Post Comment Tool — deploy on Coolify (Dockerfile build pack).
FROM node:20-alpine
# curl is required for the healthcheck — node:alpine ships without it, which made Coolify's probe
# fail with "curl: not found" and roll the deploy back even though the server was up.
RUN apk add --no-cache curl
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
# Keys live on a PERSISTENT volume so they survive redeploys (mount a volume at /data).
ENV KEYS_PATH=/data/keys.json
ENV PORT=3509
ENV NODE_ENV=production
# ★2026-08-16: production mode so Express's default error handler does NOT put err.stack in the response body (with it
# unset, an unauthenticated /api/validate 500 leaked file paths + internals). Paired with the explicit handler in license-server.js.
EXPOSE 3509
# Probe the no-auth /health route on the local port. start-period gives the server time to boot so
# early "connection refused" attempts don't count as failures.
HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=5 \
  CMD curl -fsS http://127.0.0.1:3509/health || exit 1
CMD ["node", "license-server.js"]
