use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

#[derive(Debug)]
struct LimiterState {
    rate_bytes_per_sec: u64,
    next_available_at: Instant,
}

/// 全局带宽限速器（匀速节流）
///
/// - `rate_bytes_per_sec = 0` 表示不限速
/// - 线程安全，可跨任务共享
/// - 通过“时间配额”方式平滑限速，避免突发（尽量贴近任务管理器中的直线）
#[derive(Debug, Clone)]
pub struct BandwidthLimiter {
    state: Arc<Mutex<LimiterState>>,
}

impl BandwidthLimiter {
    pub fn new(rate_bytes_per_sec: u64) -> Self {
        let now = Instant::now();
        Self {
            state: Arc::new(Mutex::new(LimiterState {
                rate_bytes_per_sec,
                next_available_at: now,
            })),
        }
    }

    pub async fn set_rate_kbps(&self, rate_kbps: u64) {
        self.set_rate_bytes_per_sec(rate_kbps.saturating_mul(1024))
            .await;
    }

    pub async fn set_rate_bytes_per_sec(&self, rate_bytes_per_sec: u64) {
        let mut state = self.state.lock().await;
        state.rate_bytes_per_sec = rate_bytes_per_sec;
        // 调整限速后重置时间基线，避免切换时堆积造成突发
        state.next_available_at = Instant::now();
    }

    pub async fn rate_bytes_per_sec(&self) -> u64 {
        let state = self.state.lock().await;
        state.rate_bytes_per_sec
    }

    pub async fn acquire(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }

        let scheduled_at = {
            let mut state = self.state.lock().await;

            if state.rate_bytes_per_sec == 0 {
                return;
            }

            let now = Instant::now();
            let start_at = state.next_available_at.max(now);
            let spend_secs = bytes as f64 / state.rate_bytes_per_sec as f64;
            let spend = std::time::Duration::from_secs_f64(spend_secs);

            state.next_available_at = start_at + spend;
            start_at
        };

        let now = Instant::now();
        if scheduled_at > now {
            tokio::time::sleep_until(tokio::time::Instant::from_std(scheduled_at)).await;
        }
    }
}
