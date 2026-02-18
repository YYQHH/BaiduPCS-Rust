use anyhow::{Context, Result};
use reqwest::{ClientBuilder, Proxy};
use serde::{Deserialize, Serialize};

/// 代理类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyType {
    /// 不使用代理
    None,
    /// HTTP 代理
    Http,
    /// SOCKS5 代理
    Socks5,
}

impl Default for ProxyType {
    fn default() -> Self {
        Self::None
    }
}

/// 网络代理配置
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyConfig {
    /// 代理类型
    #[serde(default)]
    pub proxy_type: ProxyType,
    /// 代理服务器地址（IP/域名）
    #[serde(default)]
    pub host: String,
    /// 代理端口
    #[serde(default)]
    pub port: u16,
    /// 代理认证用户名（可选）
    #[serde(default)]
    pub username: String,
    /// 代理认证密码（可选）
    #[serde(default)]
    pub password: String,
}

impl ProxyConfig {
    /// 是否启用代理
    pub fn is_enabled(&self) -> bool {
        self.proxy_type != ProxyType::None
    }

    /// 构建 reqwest Proxy
    pub fn to_reqwest_proxy(&self) -> Result<Option<Proxy>> {
        if !self.is_enabled() {
            return Ok(None);
        }

        let host = self.host.trim();
        if host.is_empty() {
            anyhow::bail!("代理已启用，但代理地址不能为空");
        }

        if self.port == 0 {
            anyhow::bail!("代理已启用，但代理端口必须在 1-65535 范围内");
        }

        let host = normalize_proxy_host(host);
        let proxy_url = match self.proxy_type {
            ProxyType::None => return Ok(None),
            ProxyType::Http => format!("http://{host}:{}", self.port),
            ProxyType::Socks5 => format!("socks5h://{host}:{}", self.port),
        };

        let mut proxy =
            Proxy::all(&proxy_url).with_context(|| format!("创建代理失败: {proxy_url}"))?;

        let username = self.username.trim();
        if !username.is_empty() {
            proxy = proxy.basic_auth(username, self.password.trim());
        }

        Ok(Some(proxy))
    }

    /// 将代理应用到 reqwest builder
    pub fn apply_to_builder(&self, builder: ClientBuilder) -> Result<ClientBuilder> {
        if let Some(proxy) = self.to_reqwest_proxy()? {
            Ok(builder.proxy(proxy))
        } else {
            Ok(builder.no_proxy())
        }
    }
}

fn normalize_proxy_host(host: &str) -> String {
    if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_proxy_host;

    #[test]
    fn normalize_ipv6_host() {
        assert_eq!(normalize_proxy_host("::1"), "[::1]");
        assert_eq!(normalize_proxy_host("[::1]"), "[::1]");
    }
}
