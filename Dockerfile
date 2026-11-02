# `docker build --target test .` runs the suite in this image.
# The demo image below does not run it.
FROM debian:bookworm AS test
# python3 and openssl run scripts/trust_chain.py in tests/trust.cpp.
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake pkg-config libssl-dev ca-certificates python3 openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Only what the build and the suite read, so a new trust chain in demo/ does not
# rebuild or retest anything.
COPY CMakeLists.txt VERSION ./
COPY cmake cmake
COPY include include
COPY src src
COPY tests tests
COPY scripts scripts
RUN cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure
# The installed package, static and shared, consumed through find_package.
RUN sh tests/package/check.sh iya_gnap iya_gnap IYA_GNAP

FROM debian:bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt VERSION ./
COPY cmake cmake
COPY include include
COPY src src
COPY tests tests
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build --target gnap-demo

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/build/gnap-demo /app/gnap-demo
COPY scripts scripts
# demo/ comes after the build. .dockerignore admits one file of demo/generated:
# idp-ca.pem, the iya-sts listener CA trust chain scripts/configure_iya_sts.py
# writes where tlsCa names it. When it exists, this COPY puts it at
# /app/demo/generated/idp-ca.pem, so the image trusts that iya-sts with no bind
# mount and no fetch; rebuild after running the install script against a
# different iya-sts. When it does not (a fresh clone, CI), the directory COPY
# still succeeds; naming the file, or a glob that matches nothing, would fail
# the build. The client key and certificate never enter the image.
COPY demo demo
EXPOSE 3000
ENV PORT=3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s \
  CMD python3 -c "import urllib.request; assert urllib.request.urlopen('http://127.0.0.1:${PORT}/healthz').read()==b'ok'" || exit 1
# Refresh the chain from the authorization server at start (a development
# iya-sts makes a new CA when it restarts), unless TLS_CA_REFRESH=0. A failed
# refresh keeps the chain from the build.
CMD ["sh", "-c", "if [ \"${TLS_CA_REFRESH:-1}\" != \"0\" ]; then python3 scripts/trust_chain.py --config \"${GNAP_CONFIG:-demo/gnap.json}\" || true; fi; exec /app/gnap-demo"]
