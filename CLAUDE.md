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

That command is the suite. The demo image does not run it. Tests use an in-process stub on 127.0.0.1. They do not need a live authorization server.

## Layout

- `include/iya/gnap.hpp` the C++ classes
- `include/iya_gnap.h` the C ABI
- `src/` the only protocol implementation: JSON, HTTP/1.1, key proofs (mtls, httpsig, jwsd), the grant client, and one poll stream
- `tests/` C cases plus one C++ smoke test, both linked to the `iya_gnap` library
- `src/demo_main.cpp` the HTTP demo; `demo/gnap.json` the sample configuration
- `scripts/configure_iya_sts.py` registers the app; `scripts/redirects.py` and `scripts/trust_chain.py` support it

## Demo

`PORT` defaults to 3000 and is the bind port. The demo listens on `PORT`. Loopback redirect and finish URLs follow `PORT`. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `ok`. `ssf.pollIntervalMs` is a millisecond interval.

## Signals

Omitted or `true` keeps CAEP and RISC on, and the resolved configuration omits `signals`. `false` does not start the receiver, does not require transmitter metadata, drops `ssf.read` and `ssf.manage`, and is kept on the resolved configuration. Anything else returns `signals must be true or false`.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.

`develop` and `main` must be the same commit. Publishing is not set up.
