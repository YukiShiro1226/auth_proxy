use anyhow::{anyhow, Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::config::Creds;
use crate::http;
use crate::netio;

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
        let (host, port) = http::parse_connect_authority(path)?;
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

    let forwarded = http::build_forwarded_request(method, &target, &headers)?;
    upstream.write_all(&forwarded).await?;

    let mut client = netio::PrefixedStream::new(client, leftover);
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;

    Ok(())
}
