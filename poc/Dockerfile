# Remote PoC client image. Pure HTTP client — no privileged access to the victim.
FROM node:22-bookworm-slim
WORKDIR /poc
COPY package.json exploit.js ./
ENTRYPOINT ["node", "exploit.js"]
