mod config;
mod http;
mod netio;
mod proxy;

use anyhow::Result;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = config::Config::from_args_env()?;

    let listener = TcpListener::bind(&cfg.listen).await?;
    eprintln!("auth_proxy listening on {}", cfg.listen);
    eprintln!("credentials: {}:********", cfg.creds.user);

    loop {
        let (stream, addr) = listener.accept().await?;
        let creds = cfg.creds.clone();

        tokio::spawn(async move {
            if let Err(e) = proxy::handle_client(stream, creds).await {
                eprintln!("[{addr}] {e:#}");
            }
        });
    }
}
