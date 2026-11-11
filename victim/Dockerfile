# Victim image for GHSA-673q-mjm6-r5xr.
#
# RSDW_VERSION selects the react-server-dom-webpack (and matching react) version:
#   19.2.8  -> VULNERABLE (same Flight code Next.js 16.4.0 bundles)
#   19.2.9  -> PATCHED    (same Flight code Next.js 16.4.1 bundles)
#
# react-server-dom-webpack is the exact React Server Components transport that
# Next.js vendors; pinning it reproduces the bug without a full Next build.
FROM node:22-bookworm-slim

ARG RSDW_VERSION=19.2.8
ENV RSDW_VERSION=${RSDW_VERSION}
ENV NODE_ENV=production

WORKDIR /app

COPY package.json ./
# Exact, reproducible pin of the vulnerable/patched transport + its React peer.
RUN npm install --no-audit --no-fund --save-exact \
      react@${RSDW_VERSION} \
      react-dom@${RSDW_VERSION} \
      react-server-dom-webpack@${RSDW_VERSION}

COPY app-modules.js server.js ./

# A fake "secret" so the PoC can demonstrate data exfiltration via RCE.
RUN printf 'DB_PASSWORD=hunter2\nAPI_KEY=sk-live-7f3c9a21b0e4\nFLAG{GHSA-673q-mjm6-r5xr-rce}\n' > /app/SECRET.txt

EXPOSE 3000
# --conditions react-server activates the RSC server entry points, exactly as a
# Next.js server runtime does.
CMD ["node", "--conditions", "react-server", "server.js"]
