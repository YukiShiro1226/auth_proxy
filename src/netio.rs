use anyhow::{bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

pub struct PrefixedStream<S> {
    inner: S,
    prefix: Vec<u8>,
    pos: usize,
}

impl<S> PrefixedStream<S> {
    pub fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self { inner, prefix, pos: 0 }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() && buf.remaining() > 0 {
            let available = self.prefix.len() - self.pos;
            let to_copy = available.min(buf.remaining());
            buf.put_slice(&self.prefix[self.pos..self.pos + to_copy]);
            self.pos += to_copy;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub async fn read_header_and_leftover<R: AsyncRead + Unpin>(
    stream: &mut R,
    max: usize,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 2048];

    loop {
        if buf.len() >= max {
            bail!("header too large (>{max} bytes)");
        }

        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            bail!("peer closed before sending full header");
        }
        buf.extend_from_slice(&tmp[..n]);

        if let Some(idx) = find_double_crlf(&buf) {
            let end = idx + 4;
            let header = buf[..end].to_vec();
            let leftover = buf[end..].to_vec();
            return Ok((header, leftover));
        }
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}
