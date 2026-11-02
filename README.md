# gnap-caep-risc

A server-side [GNAP](https://www.rfc-editor.org/rfc/rfc9635) client for C and C++. The key is registered by value and proved with mutual TLS, an HTTP message signature, or a detached JWS. Access tokens are key-bound; a bearer token is refused. One Shared Signals poll stream carries CAEP and RISC events.

The private key stays in this process. The same `gnap.json` shape as the other Iya clients loads: the JSON keys are identical.

The protocol is implemented once, in C++. `iya::gnap::Client` and `iya::gnap::SignalsReceiver` are that implementation. `iya_gnap.h` declares the same operations as `extern "C"`. Those functions call the C++ classes. C callers and C++ callers link one library.

## Build and tests

```bash
docker build --target test .
```

The `test` stage compiles the library and runs the suite. GitHub Actions uses that command. The demo image does not run the suite.

Publishing is not set up.

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

`grantEndpoint`, `transmitterIssuer`, `idTokenIssuer`, `application`, `display`, `access`, `subIdFormats`, `assertionFormats`, `keyProof`, `privateKey`, `certificate`, `finishUri`, `finishMethod`, `interactionStart`, `tlsCa`, and `ssf` (`transmitter`, `pollIntervalMs`). `privateKey` and `certificate` are PEM, `file:`, or `env:`. `keyProof` is `mtls`, `httpsig`, or `jwsd`.

## Signals

`signals` omitted or `true` keeps CAEP and RISC on. The resolved configuration omits the key, fills `ssf` from `ssf.transmitter` or `transmitterIssuer`, and asks for `ssf.read` and `ssf.manage` when `access` does not say otherwise.

`signals: false` does not start the Shared Signals receiver, does not require transmitter metadata, and drops `ssf.read` and `ssf.manage` from the GNAP access. The resolved configuration includes `signals: false`. If those two rights were the only ones, configuration fails and asks for another right the authorization server grants. Any other value fails with `signals must be true or false`.

`ssf.pollIntervalMs` is the poll interval in milliseconds.

## Demo

```bash
docker compose up --build
```

`PORT` defaults to 3000 and is the bind port. The demo listens on `PORT`. Loopback finish and display URLs follow `PORT`. Any other host is left as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `ok`. The home page has a sign-in control; `/login` starts a grant, `/callback` finishes it, and `POST /logout` signs out.

The shipped `demo/gnap.json` leaves `signals` on by omitting the key. Key material is `file:` or `env:` and is not in the tree. Register the application with:

```bash
ADMIN_API_CLIENT_SECRET=… python scripts/configure_iya_sts.py --config demo/gnap.json
```

`--dry-run` prints the admin API calls and sends nothing. When the `gnap-demo` container is running, its `PORT` wins over the shell `PORT`.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.
