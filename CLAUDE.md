# gnap-caep-risc

Server-side GNAP client for C and C++. One implementation, in C++17 (`iya::gnap`). `include/iya_gnap.h` is the `extern "C"` ABI for that same implementation. C and C++ callers link one library. Do not implement the protocol a second time, and do not wrap another language port.

```cpp
auto client = iya::gnap::Client::from_file("gnap.json");
auto started = client.request_grant();
auto done = client.finish_redirect(query, {started.pending_id});
```

`Config::from_file` and `iya_gnap_client_from_file` load the same JSON keys as the other Iya clients. C functions log a failure once and return an error code. C++ methods throw `iya::gnap::Error` and do not log again.

## Tests

```bash
docker build --target test .
```

That command is the suite. The demo image does not run it. Tests use an in-process stub on 127.0.0.1. They do not need a live authorization server. `tests/trust.cpp` covers the `tlsCa` chain, a forged leaf, the host name (with `tlsCa` and with the system roots), the mtls client certificate against a CertificateRequest naming another CA, and `trust_chain.py`.

## Live test and nightly

`python3 scripts/live_iya_sts.py` (host stdlib python3 and Docker; never CMake or a compiler on the host) starts a fresh iya-sts `main` in memory mode as container `iya-sts-live-gnap-caep-risc-c` on `LIVE_STS_PORT` (default 18527), copies the checkout to a scratch build context, builds the demo image, makes the client key and certificate with the image's openssl, runs `scripts/configure_iya_sts.py` on the host against that copy (which writes the trust chain; a `gnap_access_token` claim set refused as "not one of" is skipped, any other refusal fails), rebuilds the image (which bakes the chain in), checks the image's chain equals the saved one and that nothing else of `demo/generated` is in it, runs `gnap-caep-risc-c-live-demo` with `--network host` on `LIVE_DEMO_PORT` (default 18627) mounting only `client.key` and `client.crt` and with `TLS_CA_REFRESH=0`, signs in through `/authn-api` and `/gnap-api/approve`, emits `credential-change` then `session-revoked`, and checks `GET /live-status`. `IYA_STS_URL` and `IYA_STS_IMAGE` select an existing iya-sts or image. It never binds 3000, 8081 or 18481-18495. Always against a fresh iya-sts (a re-registered GNAP key is refused). Secrets reach `docker run` as `-e NAME` and are never printed; log lines name requests by fixed labels. `.github/workflows/nightly.yml` runs the unit image and the live script at 07:46 UTC (`46 7 * * *`).

`/live-status` is `{signedIn, subject, receiver, events: [{type, jti}]}`, never tokens. The demo (not the library) ends cookie sessions by the grant id the receiver tracks, tracks every grant, and ends its one local session on a `session-revoked` that matched none (`remember` in `src/demo_main.cpp`).

## tlsCa, the iya-sts trust chain

`tlsCa` (demo default `generated/idp-ca.pem`) is iya-sts's listener CA trust chain. `scripts/configure_iya_sts.py` writes the whole chain on every run via `scripts/trust_chain.py` (`GET /tls/server-certificate`, falling back to the handshake) and prints the path, anchor subject and SHA-256. It never prints a generated test-user password: that goes to `demo/generated/<user>.password` (0600). `src/http.cpp` (`verify_pinned`) verifies the presented chain to an anchor in the file, or accepts only when the presented LEAF is itself in the file, and checks the host name either way; without `tlsCa` it uses the system roots and sets `SSL_set1_host` / `X509_VERIFY_PARAM_set1_ip_asc` (no SNI for an IP literal). The client certificate is set on the connection with `SSL_use_certificate`, so OpenSSL sends it whatever CA names the CertificateRequest carries. The test and build stages copy only `CMakeLists.txt`, `VERSION`, `include`, `src`, `tests` (and `scripts` for the suite); the demo stage then does `COPY demo demo`, and `.dockerignore` excludes `demo/generated/*` except `idp-ca.pem`, so the image carries the chain and no key, and a build without it still succeeds. Rebuild the demo image after re-running the install script against a different iya-sts. The image's CMD still refreshes the chain at start unless `TLS_CA_REFRESH=0`.

## Layout

- `include/iya/gnap.hpp` the C++ classes
- `include/iya_gnap.h` the C ABI
- `src/` the only protocol implementation: JSON, HTTP/1.1, key proofs (mtls, httpsig, jwsd), the grant client, and one poll stream
- `tests/` C cases plus one C++ smoke test, both linked to the `iya_gnap` library
- `src/demo_main.cpp` the HTTP demo; `demo/gnap.json` the sample configuration
- `scripts/configure_iya_sts.py` registers the app and writes the `tlsCa` chain; `scripts/redirects.py` and `scripts/trust_chain.py` support it; `scripts/live_iya_sts.py` is the live sign-in

## Demo

`PORT` defaults to 3000 and is the bind port. The demo listens on `PORT`. Loopback redirect and finish URLs follow `PORT`. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `ok`. `GET /live-status` is the JSON above. `ssf.pollIntervalMs` is a millisecond interval.

## Signals

Omitted or `true` keeps CAEP and RISC on, and the resolved configuration omits `signals`. `false` does not start the receiver, does not require transmitter metadata, drops `ssf.read` and `ssf.manage`, and is kept on the resolved configuration. Anything else returns `signals must be true or false`.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.

`develop` and `main` must be the same commit. The library is a CMake package: `find_package(iya_gnap)` gives `iya::gnap`; static by default, shared with `BUILD_SHARED_LIBS`; `IYA_GNAP_BUILD_TESTS` and `IYA_GNAP_BUILD_PROGRAMS` default on only at the top level. `tests/package/check.sh` (run by the Docker test stage) installs both variants and builds the smoke test against each. A pull request merged into `main` releases the library after the test workflow succeeds on that commit: `release.yml` tags `v<VERSION>` and makes a GitHub Release, whose source archive is what a package recipe (such as a ConanCenter one) builds from. A direct push does not release. A tag that already exists stays. A pull request into `main` that changes the library must raise `VERSION`, which the CMake project, the package and the tag all read: `version-check.yml` fails it otherwise, so the bump lands on `develop` first. `release.yml` then tags the merge commit on `main`, and a change to tests, the demo, or the docs releases nothing. The root `conanfile.py` is the clone-and-`conan create` recipe ConanCenter's maintainers recommended when they declined the package (conan-io/conan-center-index#31317–#31320, 2026-11-03): it builds from the checkout's own files (`exports_sources`), takes its version from `VERSION` and refuses a different `--version`, and runs `conan/all/test_package`. `conan/` stays for a later ConanCenter submission.
