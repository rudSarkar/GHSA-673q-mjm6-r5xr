# Hermetic root-cause evidence runner. Installs BOTH the vulnerable (19.2.8) and
# patched (19.2.9) react-server-dom-webpack and runs the three reproducers.
FROM node:22-bookworm-slim
WORKDIR /evidence
COPY 00-arraybuffer-detach.mjs 01-encoder-desync.cjs 02-type-confusion-sink.cjs 03-full-chain-rce.cjs run.sh ./
RUN chmod +x run.sh
ENV WORK=/work
ENTRYPOINT ["./run.sh"]
