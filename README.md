# Simple Rust HTTP Proxy with Basic Authentication

A minimal, production-oriented **HTTP forward proxy** written in **Rust** that performs **username/password authentication** before proxying requests.

This project is designed to be easy to run and easy to integrate into automation or deployments where you need a lightweight authenticated proxy.

---

## Features

- ✅ HTTP proxy server (forward proxy)
- ✅ Username/password authentication (Basic-style credentials check)
- ✅ Simple CLI interface
- ✅ Runs on any host/port you choose
- ✅ Suitable for local testing, containers, and servers

---

## Requirements

- Rust toolchain installed (stable)
  - Install from: https://rustup.rs

---

## Build

```bash
cargo build --release
```
The compiled binary will be located at:
target/release/auth_proxy

## Run

### Usage

```bash
cargo run --release -- <LISTEN_ADDR> <USERNAME> <PASSWORD>
```

### Example

```bash
cargo run --release -- 0.0.0.0:8080 username password
```

### Notes

- `0.0.0.0` binds on all network interfaces, so the proxy may be reachable from other machines if your firewall/security group allows it.
- For local-only access, bind to `127.0.0.1`:

```bash
cargo run --release -- 127.0.0.1:8080 username password
```
- Use a strong password if you expose the proxy beyond your local machine.


## Using the Proxy

After starting the proxy, configure your application or tool to use it as an HTTP proxy:

```text
http://<HOST>:<PORT>
```

### Authentication

When prompted for proxy credentials (or when your client supports proxy auth), use:
- Username: <USERNAME>
- Password: <PASSWORD>

### Common Examples

cURL

```bash
curl -x http://<HOST>:<PORT> -U <USERNAME>:<PASSWORD> http://example.com
```

Environment variables (many CLI tools respect these)

```bash
export HTTP_PROXY="http://<USERNAME>:<PASSWORD>@<HOST>:<PORT>"
export HTTPS_PROXY="http://<USERNAME>:<PASSWORD>@<HOST>:<PORT>"
```
