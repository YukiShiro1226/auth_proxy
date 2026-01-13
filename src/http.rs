use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use httparse::Status;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::config::Creds;

pub struct ParsedReq<'a> {
    pub method: Option<&'a str>,
    pub path: Option<&'a str>,
}

pub fn parse_request(header: &[u8]) -> Result<(ParsedReq<'_>, Vec<(String, Vec<u8>)>)> {
    let mut headers_arr = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers_arr);

    match req.parse(header)? {
        Status::Complete(_) => {}
        Status::Partial => bail!("incomplete header"),
    }

    let method = req.method;
    let path = req.path;

    let mut headers = Vec::new();
    for h in req.headers.iter() {
        if h.name.is_empty() {
            continue;
        }
        headers.push((h.name.to_string(), h.value.to_vec()));
    }

    Ok((ParsedReq { method, path }, headers))
}

pub fn is_authorized(headers: &[(String, Vec<u8>)], creds: &Creds) -> Result<bool> {
    let mut auth_val: Option<String> = None;

    for (k, v) in headers {
        if k.eq_ignore_ascii_case("Proxy-Authorization") || k.eq_ignore_ascii_case("Authorization") {
            auth_val = Some(String::from_utf8_lossy(v).to_string());
            break;
        }
    }

    let Some(auth) = auth_val else {
        return Ok(false);
    };

    let auth = auth.trim();
    let rest = auth.strip_prefix("Basic ").or_else(|| auth.strip_prefix("basic "));
    let Some(b64) = rest else {
        return Ok(false);
    };

    let decoded = B64
        .decode(b64.trim())
        .map_err(|_| anyhow!("invalid base64 in Proxy-Authorization"))?;

    let decoded = String::from_utf8(decoded).map_err(|_| anyhow!("non-utf8 credentials"))?;
    Ok(decoded == format!("{}:{}", creds.user, creds.pass))
}

pub async fn write_407<W: AsyncWrite + Unpin>(w: &mut W) -> Result<()> {
    let resp = concat!(
        "HTTP/1.1 407 Proxy Authentication Required\r\n",
        "Proxy-Authenticate: Basic realm=\"auth_proxy\"\r\n",
        "Connection: close\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "Content-Length: 30\r\n",
        "\r\n",
        "Proxy Authentication Required\n"
    );
    w.write_all(resp.as_bytes()).await?;
    w.flush().await?;
    Ok(())
}

pub async fn write_400<W: AsyncWrite + Unpin>(w: &mut W, msg: &[u8]) -> Result<()> {
    let mut resp = Vec::new();
    resp.extend_from_slice(b"HTTP/1.1 400 Bad Request\r\n");
    resp.extend_from_slice(b"Connection: close\r\n");
    resp.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n");
    resp.extend_from_slice(format!("Content-Length: {}\r\n", msg.len()).as_bytes());
    resp.extend_from_slice(b"\r\n");
    resp.extend_from_slice(msg);
    w.write_all(&resp).await?;
    w.flush().await?;
    Ok(())
}

pub fn parse_connect_authority(authority: &str) -> Result<(String, u16)> {
    let mut parts = authority.split(':');
    let host = parts
        .next()
        .ok_or_else(|| anyhow!("CONNECT missing host"))?
        .trim()
        .to_string();
    let port_str = parts
        .next()
        .ok_or_else(|| anyhow!("CONNECT missing port"))?
        .trim();
    let port: u16 = port_str.parse().context("invalid CONNECT port")?;
    Ok((host, port))
}

pub struct HttpTarget {
    pub host: String,
    pub port: u16,
    pub path: String,       // origin-form path (/... or /?...)
    pub host_header: String,
    pub is_https: bool,
}

pub fn parse_http_target(path: &str, headers: &[(String, Vec<u8>)]) -> Result<HttpTarget> {
    // absolute-form: http://host[:port]/path
    if let Some(rest) = path.strip_prefix("http://") {
        let (authority, origin_path) = split_authority_and_path(rest);
        let (host, port) = parse_host_port(authority, 80)?;
        let host_header = if port == 80 { host.clone() } else { format!("{host}:{port}") };
        return Ok(HttpTarget {
            host,
            port,
            path: origin_path.to_string(),
            host_header,
            is_https: false,
        });
    }

    if path.starts_with("https://") {
        // We intentionally do not implement https absolute-form here.
        // Clients should use CONNECT for https://
        return Ok(HttpTarget {
            host: "".to_string(),
            port: 443,
            path: "/".to_string(),
            host_header: "".to_string(),
            is_https: true,
        });
    }

    // origin-form: path starts with /, use Host header
    let host_hdr = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Host"))
        .map(|(_, v)| String::from_utf8_lossy(v).trim().to_string())
        .ok_or_else(|| anyhow!("origin-form request missing Host header"))?;

    let (host, port) = parse_host_port(&host_hdr, 80)?;
    let host_header = if port == 80 { host.clone() } else { format!("{host}:{port}") };

    Ok(HttpTarget {
        host,
        port,
        path: if path.is_empty() { "/".to_string() } else { path.to_string() },
        host_header,
        is_https: false,
    })
}

fn split_authority_and_path(rest: &str) -> (&str, &str) {
    if let Some(slash) = rest.find('/') {
        let (a, p) = rest.split_at(slash);
        (a, p)
    } else {
        (rest, "/")
    }
}

fn parse_host_port(authority: &str, default_port: u16) -> Result<(String, u16)> {
    // simple "host" or "host:port" (no IPv6 bracket support in this compact version)
    if let Some((h, p)) = authority.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return Ok((h.to_string(), port));
        }
    }
    Ok((authority.to_string(), default_port))
}

pub fn build_forwarded_request(
    method: &str,
    target: &HttpTarget,
    headers: &[(String, Vec<u8>)],
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1024);

    // Request line (origin-form)
    out.extend_from_slice(method.as_bytes());
    out.extend_from_slice(b" ");
    out.extend_from_slice(target.path.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");

    let mut saw_host = false;

    for (k, v) in headers {
        // Strip proxy-only / connection headers
        if k.eq_ignore_ascii_case("Proxy-Authorization")
            || k.eq_ignore_ascii_case("Proxy-Connection")
            || k.eq_ignore_ascii_case("Connection")
            || k.eq_ignore_ascii_case("Keep-Alive")
        {
            continue;
        }

        if k.eq_ignore_ascii_case("Host") {
            saw_host = true;
            out.extend_from_slice(b"Host: ");
            out.extend_from_slice(target.host_header.as_bytes());
            out.extend_from_slice(b"\r\n");
            continue;
        }

        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v);
        out.extend_from_slice(b"\r\n");
    }

    if !saw_host {
        out.extend_from_slice(b"Host: ");
        out.extend_from_slice(target.host_header.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    // Keep it simple: one request per connection
    out.extend_from_slice(b"Connection: close\r\n");
    out.extend_from_slice(b"\r\n");
    Ok(out)
}
