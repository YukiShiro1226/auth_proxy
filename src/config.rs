use anyhow::Result;
use std::env;

#[derive(Clone)]
pub struct Creds {
    pub user: String,
    pub pass: String,
}

pub struct Config {
    pub listen: String,
    pub creds: Creds,
}

impl Config {
    /// Args: [listen] [user] [pass]
    /// Or env: PROXY_LISTEN, PROXY_USER, PROXY_PASS
    pub fn from_args_env() -> Result<Self> {
        let mut args = env::args().skip(1);

        let listen = args
            .next()
            .or_else(|| env::var("PROXY_LISTEN").ok())
            .unwrap_or_else(|| "0.0.0.0:8080".to_string());

        let user = args
            .next()
            .or_else(|| env::var("PROXY_USER").ok())
            .unwrap_or_else(|| "user".to_string());

        let pass = args
            .next()
            .or_else(|| env::var("PROXY_PASS").ok())
            .unwrap_or_else(|| "pass".to_string());

        Ok(Self {
            listen,
            creds: Creds { user, pass },
        })
    }
}
