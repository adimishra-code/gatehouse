# Gatehouse gateway binary — multi-stage, runs as nobody.
FROM rust:1-slim AS build
WORKDIR /src
COPY gatehouse/Cargo.toml gatehouse/Cargo.lock* ./
COPY gatehouse/src ./src
RUN cargo build --release

# Console is built inside the image so `docker compose up` needs zero prep.
FROM node:22-slim AS console
WORKDIR /app
COPY console/package.json console/package-lock.json* ./
RUN npm install --no-fund --no-audit
COPY console/ ./
RUN npm run build

# The demo stdio server is bundled so the stack works out of the box.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends nodejs ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/gatehouse /usr/local/bin/gatehouse
COPY demo/mcp-echo-server.mjs /opt/demo/mcp-echo-server.mjs
COPY --from=console /app/dist /opt/console/dist
COPY deploy/gatehouse.docker.toml /etc/gatehouse.toml
RUN useradd -r -u 901 gatehouse && mkdir -p /data && chown gatehouse /data
USER gatehouse
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["gatehouse"]
CMD ["/etc/gatehouse.toml"]
