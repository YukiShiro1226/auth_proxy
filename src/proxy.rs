use anyhow::{anyhow, bail, Context, Result};
use flate2::read::GzDecoder;
use std::io::Read;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::config::Creds;
use crate::{http, netio};

const MAX_LOG_BYTES: usize = 64 * 1024;
const MAX_DECODED_LOG_BYTES: usize = 256 * 1024;

pub async fn handle_client(mut client: TcpStream, creds: Creds) -> Result<()> {
    let (header, leftover) = netio::read_header_and_leftover(&mut client, 64 * 1024).await?;
    let (req, headers) = http::parse_request(&header)?;

    if !http::is_authorized(&headers, &creds)? {
        http::write_407(&mut client).await?;
        return Ok(());
    }

    let method = req.method.ok_or_else(|| anyhow!("missing method"))?;
    let path = req.path.ok_or_else(|| anyhow!("missing path"))?;

    if method.eq_ignore_ascii_case("CONNECT") {
        // HTTPS tunnel: cannot see plaintext bodies without terminating TLS.
        let (host, port) = http::parse_connect_authority(path)?;
        eprintln!("[CONNECT] {}:{} (tunnel; bodies not visible)", host, port);

        let mut upstream = TcpStream::connect((host.as_str(), port))
            .await
            .with_context(|| format!("connect to {host}:{port} failed"))?;

        let mut client = netio::PrefixedStream::new(client, leftover);

        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        return Ok(());
    }

    let target = http::parse_http_target(path, &headers)?;
    if target.is_https {
        http::write_400(&mut client, b"Use CONNECT for https:// URLs.\n").await?;
        return Ok(());
    }

    let mut upstream = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .with_context(|| format!("connect to {}:{} failed", target.host, target.port))?;

    // Send rewritten request header upstream
    let forwarded = http::build_forwarded_request(method, &target, &headers)?;
    upstream.write_all(&forwarded).await?;

    // From here, use a prefixed client stream so we can read any body bytes already read.
    let mut client = netio::PrefixedStream::new(client, leftover);

    // ---- Request body: forward + capture (payload only) ----
    let req_ct = http::header_value_string(&headers, "Content-Type");
    let req_ce = http::header_value_string(&headers, "Content-Encoding");

    let mut req_capture = Vec::new();
    let req_len = http::content_length(&headers);
    if http::is_chunked(&headers) {
        let _ = forward_chunked_body(&mut client, &mut upstream, &mut req_capture, MAX_LOG_BYTES).await?;
    } else if let Some(len) = req_len {
        let _ = forward_fixed_body(&mut client, &mut upstream, len, &mut req_capture, MAX_LOG_BYTES).await?;
    } else {
        // No Content-Length/chunked => assume no body (common for GET).
    }

    if !req_capture.is_empty() {
        log_body("REQUEST", req_ct.as_deref(), req_ce.as_deref(), &req_capture, req_len);
    }

    // ---- Response header ----
    let (resp_header, resp_leftover) = netio::read_header_and_leftover(&mut upstream, 64 * 1024).await?;
    let (resp, resp_headers) = http::parse_response(&resp_header)?;

    let code = resp.code.unwrap_or(0);
    let reason = resp.reason.unwrap_or("");
    eprintln!("[HTTP] <- {code} {reason}");

    client.write_all(&resp_header).await?;


    // Prefixed upstream so leftover body bytes are included
    let mut upstream = netio::PrefixedStream::new(upstream, resp_leftover);

    // ---- Response body: forward + capture (payload only) ----
    let resp_ct = http::header_value_string(&resp_headers, "Content-Type");
    let resp_ce = http::header_value_string(&resp_headers, "Content-Encoding");

    let mut resp_capture = Vec::new();
    let resp_len = http::content_length(&resp_headers);

    if http::is_chunked(&resp_headers) {
        let _ = forward_chunked_body(&mut upstream, &mut client, &mut resp_capture, MAX_LOG_BYTES).await?;
    } else if let Some(len) = resp_len {
        let _ = forward_fixed_body(&mut upstream, &mut client, len, &mut resp_capture, MAX_LOG_BYTES).await?;
    } else {
        let _ = forward_until_eof(&mut upstream, &mut client, &mut resp_capture, MAX_LOG_BYTES).await?;
    }

    if !resp_capture.is_empty() {
        log_body("RESPONSE", resp_ct.as_deref(), resp_ce.as_deref(), &resp_capture, resp_len);
    }

    Ok(())
}

async fn forward_fixed_body<R, W>(
    r: &mut R,
    w: &mut W,
    len: usize,
    capture: &mut Vec<u8>,
    max_capture: usize,
) -> Result<usize>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut remaining = len;
    let mut buf = vec![0u8; 8192];
    let mut total = 0usize;

    while remaining > 0 {
        let to_read = remaining.min(buf.len());
        let n = r.read(&mut buf[..to_read]).await?;
        if n == 0 {
            bail!("unexpected EOF while reading fixed-length body");
        }
        w.write_all(&buf[..n]).await?;
        capture_bytes(capture, &buf[..n], max_capture);
        total += n;
        remaining -= n;
    }
    w.flush().await?;
    Ok(total)
}

async fn forward_until_eof<R, W>(
    r: &mut R,
    w: &mut W,
    capture: &mut Vec<u8>,
    max_capture: usize,
) -> Result<usize>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 8192];
    let mut total = 0usize;

    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        w.write_all(&buf[..n]).await?;
        capture_bytes(capture, &buf[..n], max_capture);
        total += n;
    }
    w.flush().await?;
    Ok(total)
}

async fn forward_chunked_body<R, W>(
    r: &mut R,
    w: &mut W,
    capture: &mut Vec<u8>,
    max_capture: usize,
) -> Result<usize>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut br = BufReader::new(r);
    let mut total_forwarded = 0usize;

    loop {
        // Read chunk-size line (includes CRLF)
        let mut line = Vec::new();
        let n = br.read_until(b'\n', &mut line).await?;
        if n == 0 {
            bail!("unexpected EOF while reading chunk size");
        }
        w.write_all(&line).await?;
        total_forwarded += n;

        let chunk_size = parse_chunk_size(&line)?;

        if chunk_size == 0 {
            // Forward trailers until blank line
            loop {
                let mut tline = Vec::new();
                let m = br.read_until(b'\n', &mut tline).await?;
                if m == 0 {
                    bail!("unexpected EOF while reading chunk trailers");
                }
                w.write_all(&tline).await?;
                total_forwarded += m;

                if tline == b"\r\n" || tline == b"\n" {
                    w.flush().await?;
                    return Ok(total_forwarded);
                }
            }
        }

        // Read chunk payload
        let mut chunk = vec![0u8; chunk_size];
        br.read_exact(&mut chunk).await?;
        w.write_all(&chunk).await?;
        total_forwarded += chunk_size;

        capture_bytes(capture, &chunk, max_capture);

        // Read CRLF after payload
        let mut crlf = [0u8; 2];
        br.read_exact(&mut crlf).await?;
        w.write_all(&crlf).await?;
        total_forwarded += 2;
    }
}

fn parse_chunk_size(line: &[u8]) -> Result<usize> {
    let s = std::str::from_utf8(line)
        .context("chunk size line not utf-8")?
        .trim(); // removes \r\n and whitespace
    let hex = s.split(';').next().unwrap_or("").trim();
    usize::from_str_radix(hex, 16).context("invalid chunk size hex")
}

fn capture_bytes(capture: &mut Vec<u8>, data: &[u8], max_capture: usize) {
    if capture.len() >= max_capture {
        return;
    }
    let remaining = max_capture - capture.len();
    capture.extend_from_slice(&data[..data.len().min(remaining)]);
}

fn log_body(tag: &str, content_type: Option<&str>, content_encoding: Option<&str>, raw: &[u8], total_len: Option<usize>) {
    let (decoded, decode_note, decoded_truncated) = maybe_decode_for_log(raw, content_encoding);

    let ct = content_type.unwrap_or("-");
    let ce = content_encoding.unwrap_or("-");
    let total = total_len.map(|n| n.to_string()).unwrap_or_else(|| "?".to_string());

    let truncated = if raw.len() >= MAX_LOG_BYTES { " (truncated capture)" } else { "" };
    let dec_trunc = if decoded_truncated { " (decoded truncated)" } else { "" };

    eprintln!(
        "\n===== {tag} BODY =====\nContent-Type: {ct}\nContent-Encoding: {ce}\nDeclared-Length: {total}\nCaptured: {} bytes{truncated}\nDecoded: {} bytes{dec_trunc}{decode_note}\n----- BEGIN {tag} TEXT -----",
        raw.len(),
        decoded.len()
    );

    if is_probably_text(content_type) {
        eprintln!("{}", sanitize_utf8(&String::from_utf8_lossy(&decoded)));
    } else {
        // Non-text type: still try to show UTF-8 if it looks valid-ish, otherwise hex snippet.
        if std::str::from_utf8(&decoded).is_ok() {
            eprintln!("{}", sanitize_utf8(&String::from_utf8_lossy(&decoded)));
        } else {
            let hex = decoded.iter().take(512).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
            eprintln!("<non-text/binary> first {} bytes hex:\n{}", decoded.len().min(512), hex);
        }
    }

    eprintln!("----- END {tag} TEXT -----\n=========================\n");
}

fn is_probably_text(content_type: Option<&str>) -> bool {
    let Some(ct) = content_type else { return false };
    let ct = ct.to_ascii_lowercase();
    ct.starts_with("text/")
        || ct.contains("json")
        || ct.contains("xml")
        || ct.contains("javascript")
        || ct.contains("x-www-form-urlencoded")
}

fn sanitize_utf8(s: &str) -> String {
    // Keep readable, escape control chars except \n \r \t
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\n' | '\r' | '\t' => out.push(ch),
            c if c.is_control() => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn maybe_decode_for_log(raw: &[u8], content_encoding: Option<&str>) -> (Vec<u8>, &'static str, bool) {
    let Some(enc) = content_encoding else {
        return (raw.to_vec(), "", false);
    };
    let enc_lc = enc.to_ascii_lowercase();

    if enc_lc.contains("gzip") {
        match gunzip_limited(raw, MAX_DECODED_LOG_BYTES) {
            Ok((v, truncated)) => {
                let note = if truncated { " [gunzip]" } else { " [gunzip]" };
                return (v, note, truncated);
            }
            Err(_) => {
                return (raw.to_vec(), " [gunzip failed; showing raw]", false);
            }
        }
    }

    // Unknown encoding: show raw
    (raw.to_vec(), " [unknown/unsupported encoding; showing raw]", false)
}

fn gunzip_limited(input: &[u8], max_out: usize) -> Result<(Vec<u8>, bool)> {
    let mut dec = GzDecoder::new(input);
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    let mut truncated = false;

    loop {
        let n = dec.read(&mut buf).map_err(|e| anyhow!("gunzip error: {e}"))?;
        if n == 0 {
            break;
        }

        let remaining = max_out.saturating_sub(out.len());
        if remaining == 0 {
            truncated = true;
            break;
        }

        let take = n.min(remaining);
        out.extend_from_slice(&buf[..take]);
        if take < n {
            truncated = true;
            break;
        }
    }

    Ok((out, truncated))
}
