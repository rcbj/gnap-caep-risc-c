# gnap-caep-risc

A server-side [GNAP](https://www.rfc-editor.org/rfc/rfc9635) client for C and C++. The key is registered by value and proved with mutual TLS, an HTTP message signature, or a detached JWS. Access tokens are key-bound; a bearer token is refused. One Shared Signals poll stream carries CAEP and RISC events.

The private key stays in this process. The same `gnap.json` shape as the other Iya clients loads: the JSON keys are identical.

The protocol is implemented once, in C++. `iya::gnap::Client` and `iya::gnap::SignalsReceiver` are that implementation. `iya_gnap.h` declares the same operations as `extern "C"`. Those functions call the C++ classes. C callers and C++ callers link one library.

## Build and tests

```bash
docker build --target test .
```

The `test` stage compiles the library and runs the suite. GitHub Actions uses that command. The demo image does not run the suite. `tests/trust.cpp` serves HTTPS from a four-certificate chain shaped like iya-sts's and checks that the whole `tlsCa` chain file is the trust store (another root is refused; a file holding exactly the presented leaf pins it), that a forged leaf followed by the real CA certificates is refused, that the host name is verified with `tlsCa` and with the system roots (right chain, wrong name refused; a DNS name and `127.0.0.1` via an IP SAN accepted), that the `mtls` proof presents its registered self-signed certificate when the server's CertificateRequest names only its own CA, and that `scripts/trust_chain.py` writes the whole chain from `GET /tls/server-certificate` and from the handshake.

## Live iya-sts test and the nightly suite

```bash
python3 scripts/live_iya_sts.py
```

The script starts the latest `main` of iya-sts in a container (memory mode, no persistence, no clustering), makes the client key and self-signed certificate with openssl in the demo image, registers the demo with it, signs in through the demo, emits CAEP `credential-change` and then `session-revoked`, and requires the demo's `GET /live-status` to show both, the second one with the local session ended. It prints JSON ending in `"ok": true`. `IYA_STS_URL` uses an iya-sts that is already running (and does not stop it), `IYA_STS_IMAGE` starts a fresh container from that image, and otherwise iya-sts `main` is cloned and built. `LIVE_STS_PORT` (default 18527) and `LIVE_DEMO_PORT` (default 18627) are the host ports; 3000, 8081 and 18481-18495 are refused. Always use a fresh iya-sts: a second run against an already-registered GNAP application is refused. The library and the demo build and run only in containers; the script needs the host's `python3` (standard library) and Docker.

`GET /live-status` answers `{"signedIn", "subject", "receiver", "events": [{"type", "jti"}]}` and never a token. The demo tracks every grant by its grant id. When a `session-revoked` event matches no tracked session, the demo ends its one local session and untracks it.

`.github/workflows/nightly.yml` runs the unit suite and the live script every day at 07:46 UTC (`46 7 * * *`), and on demand. Push and pull-request CI stays in `tests.yml`.

## The iya-sts trust chain (`tlsCa`)

`tlsCa` (demo default `generated/idp-ca.pem`, relative to `demo/`) is iya-sts's TLS listener CA trust chain. `scripts/configure_iya_sts.py` writes it on every run through `scripts/trust_chain.py`: the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain presented in the TLS handshake when that is missing. It prints the path, the anchor's subject and its SHA-256.

The library reads every PEM block of `tlsCa` and verifies the presented chain to the self-signed Root in it, or accepts a presented leaf that is itself in the file. Either way the certificate must name the host in the URL: a DNS name against a DNS SAN, an IP literal (such as `127.0.0.1`) against an IP SAN. A forged leaf sent ahead of the real CA certificates is refused. Without `tlsCa` the system roots are used, and the host name is still checked. Only `insecure` skips both.

The demo image build copies `demo/` after compiling, and `.dockerignore` admits only `demo/generated/idp-ca.pem` from `demo/generated`, so the image carries the chain at `/app/demo/generated/idp-ca.pem` with no bind mount. The client key and certificate stay out of the image. A build before the install script has run still succeeds; the image then has no chain. Rebuild the image after re-running the install script against a different iya-sts. The container also refreshes the chain at start unless `TLS_CA_REFRESH=0`.

## Using it from CMake

The build installs the library, its public headers and a CMake package. It builds static by
default and shared with `-DBUILD_SHARED_LIBS=ON`; `-DIYA_GNAP_BUILD_TESTS=OFF -DIYA_GNAP_BUILD_PROGRAMS=OFF`
builds the library alone (both are on only when this is the top-level project). Then:

```cmake
find_package(iya_gnap REQUIRED)
target_link_libraries(app PRIVATE iya::gnap)
```

The package finds the library's own dependencies, and the target carries the include
directory and C++17. The Docker test stage checks this: it installs the static and the shared
library and builds the C++ smoke test against each through `find_package` (`tests/package/`).

A pull request merged into `main` releases the library after the test workflow succeeds on that commit: `release.yml` tags `v<VERSION>` and makes a GitHub Release, whose source archive is what a package recipe (such as a ConanCenter one) builds from. A direct push does not release. A tag that already exists stays; the next release is a new version in `VERSION`, which the CMake project, the package and the tag all read.

## Using it from Conan

`conanfile.py` at the root of this repository builds the library from the checkout and puts
the package `iya-gnap-caep-risc` in your local Conan cache (Conan 2, a C++17 profile). Clone a release
tag and create it:

```sh
git clone --branch v0.1.1 https://github.com/rcbj/gnap-caep-risc-c.git
conan create gnap-caep-risc-c --version=0.1.1 --build=missing
```

`--version` may be left out, since the recipe reads `VERSION`; given, it must match.
`-o "iya-gnap-caep-risc/*:shared=True"` builds the shared library; the recipe refuses Windows, which
the library does not support yet. A project then requires it like any other package:

```
[requires]
iya-gnap-caep-risc/0.1.1

[generators]
CMakeDeps
CMakeToolchain
```

and finds it with `find_package(iya_gnap REQUIRED)` as above. The package is not on
ConanCenter: its maintainers asked for a longer history before including it. `conan/` keeps
the ConanCenter-layout recipe, which builds from the release archive instead of a checkout.

## C API

`iya_gnap.h` loads a configuration, requests a grant, finishes a redirect or push, verifies an ID token, and polls a Shared Signals transmitter. A failing call writes one line to stderr and returns `-1` with an `iya_gnap_error`. Strings from the library are released with `iya_gnap_free`.

```c
iya_gnap_error err = {0};
iya_gnap_client *client = iya_gnap_client_from_file("gnap.json", &err);
iya_gnap_result *started = iya_gnap_request_grant(client, &err);
const char *allowed[] = {iya_gnap_result_pending_id(started)};
iya_gnap_grant *done = iya_gnap_finish_redirect(client, query, allowed, 1, &err);
```

`iya_gnap_resolve` and `iya_gnap_resolve_file` load the same document without starting a grant. `access_json` is the resolved access list. `signals` is `-1` when CAEP and RISC stay on, and `0` when `signals` is false.

## C++ API

The C++ classes are the implementation the C functions call. A method throws `std::runtime_error` (`iya::gnap::Error`) and does not log again.

```cpp
auto client = iya::gnap::Client::from_file("gnap.json");
auto started = client.request_grant();
auto done = client.finish_redirect(query, {started.pending_id});
```

`Config::resolve_json` and `Config::from_file` load the same JSON keys. `SignalsReceiver` polls `urn:ietf:rfc:8936` with the GNAP token and acknowledges.

## JSON keys

`grantEndpoint`, `transmitterIssuer`, `idTokenIssuer`, `application`, `display`, `access`, `subIdFormats`, `assertionFormats`, `keyProof`, `privateKey`, `certificate`, `finishUri`, `finishMethod`, `interactionStart`, `tlsCa` (the authorization server's TLS listener CA trust chain, see below), and `ssf` (`transmitter`, `pollIntervalMs`). `privateKey` and `certificate` are PEM, `file:`, or `env:`. `keyProof` is `mtls`, `httpsig`, or `jwsd`.

## Signals

`signals` omitted or `true` keeps CAEP and RISC on. The resolved configuration omits the key, fills `ssf` from `ssf.transmitter` or `transmitterIssuer`, and asks for `ssf.read` and `ssf.manage` when `access` does not say otherwise.

`signals: false` does not start the Shared Signals receiver, does not require transmitter metadata, and drops `ssf.read` and `ssf.manage` from the GNAP access. The resolved configuration includes `signals: false`. If those two rights were the only ones, configuration fails and asks for another right the authorization server grants. Any other value fails with `signals must be true or false`.

`ssf.pollIntervalMs` is the poll interval in milliseconds.

## Demo

```bash
docker compose up --build
```

`PORT` defaults to 3000 and is the bind port. The demo listens on `PORT`. Loopback finish and display URLs follow `PORT`. Any other host is left as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `ok`. The home page has a sign-in control; `/login` starts a grant, `/callback` finishes it, `POST /logout` signs out, and `GET /live-status` reports the sign-in and the accepted Shared Signals events as JSON, without tokens.

The shipped `demo/gnap.json` leaves `signals` on by omitting the key. Key material is `file:` or `env:` and is not in the tree. Register the application with:

```bash
ADMIN_API_CLIENT_SECRET=… python scripts/configure_iya_sts.py --config demo/gnap.json
```

It also writes the trust chain to `demo/generated/idp-ca.pem`; rebuild the demo image afterwards (`docker compose up --build`). A generated test-user password is never printed: it is written to `demo/generated/<user>.password` (mode 0600) and only that path is printed. `--dry-run` prints the admin API calls and sends nothing. When the `gnap-demo` container is running, its `PORT` wins over the shell `PORT`.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.
