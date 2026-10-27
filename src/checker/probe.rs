use super::engine::ScanConfig;
use crate::browser::{runner::Observation, transport::HttpProbe};
use anyhow::{Context, Result};
use std::time::Duration;

pub(super) struct Probe(HttpProbe);
impl Probe {
    #[cfg(test)]
    pub(super) fn identify(&mut self, id: i64) {
        self.0.identify(id);
    }
    #[cfg(test)]
    pub(super) fn local(cert: Vec<u8>) -> Self {
        Self(HttpProbe::synthetic_with_root(cert).unwrap())
    }
    pub fn fork(&self) -> Self {
        Self(self.0.fork())
    }
    pub fn open(config: &ScanConfig) -> Result<Self> {
        #[cfg(test)]
        if !config.require_login {
            return Ok(Self(HttpProbe::synthetic_session()?));
        }
        Ok(Self(HttpProbe::load(
            config
                .browser_root
                .as_deref()
                .context("Google profile is missing")?,
            &config.browser_path,
        )?))
    }
    pub async fn check_with_timeout(
        &mut self,
        proxy: &str,
        budget: Duration,
    ) -> Result<Observation> {
        self.0.check(proxy, budget).await
    }
}
