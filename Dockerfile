# `docker build --target test` runs the suite in this image.
# The demo image below does not run it.
FROM debian:bookworm AS test
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure

FROM debian:bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build --target gnap-demo

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/build/gnap-demo /app/gnap-demo
COPY demo demo
COPY scripts scripts
EXPOSE 3000
ENV PORT=3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s \
  CMD python3 -c "import urllib.request; assert urllib.request.urlopen('http://127.0.0.1:${PORT}/healthz').read()==b'ok'" || exit 1
CMD ["sh", "-c", "python3 scripts/trust_chain.py --config \"${GNAP_CONFIG:-demo/gnap.json}\" || true; exec /app/gnap-demo"]
