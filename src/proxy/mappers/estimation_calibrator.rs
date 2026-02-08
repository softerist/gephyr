use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use tracing::info;
pub struct EstimationCalibrator {
    total_estimated: AtomicU64,
    total_actual: AtomicU64,
    sample_count: AtomicU64,
    calibration_factor: RwLock<f32>,
}

impl EstimationCalibrator {
    pub const fn new() -> Self {
        Self {
            total_estimated: AtomicU64::new(0),
            total_actual: AtomicU64::new(0),
            sample_count: AtomicU64::new(0),
            calibration_factor: RwLock::new(2.0),
        }
    }
    pub fn record(&self, estimated: u32, actual: u32) {
        if estimated == 0 || actual == 0 {
            return;
        }

        self.total_estimated
            .fetch_add(estimated as u64, Ordering::Relaxed);
        self.total_actual
            .fetch_add(actual as u64, Ordering::Relaxed);
        let count = self.sample_count.fetch_add(1, Ordering::Relaxed) + 1;
        if count % 5 == 0 {
            self.update_calibration();
        }
    }
    fn update_calibration(&self) {
        let estimated = self.total_estimated.load(Ordering::Relaxed) as f64;
        let actual = self.total_actual.load(Ordering::Relaxed) as f64;

        if estimated > 0.0 {
            let new_factor = (actual / estimated) as f32;
            let clamped = new_factor.clamp(0.8, 4.0);

            if let Ok(mut factor) = self.calibration_factor.write() {
                let old = *factor;
                *factor = old * 0.6 + clamped * 0.4;

                info!(
                    "[Calibrator] Updated factor: {:.2} -> {:.2} (raw: {:.2}, samples: {})",
                    old,
                    *factor,
                    new_factor,
                    self.sample_count.load(Ordering::Relaxed)
                );
            }
        }
    }
    pub fn calibrate(&self, estimated: u32) -> u32 {
        let factor = self.calibration_factor.read().map(|f| *f).unwrap_or(2.0);

        (estimated as f32 * factor).ceil() as u32
    }
    pub fn get_factor(&self) -> f32 {
        self.calibration_factor.read().map(|f| *f).unwrap_or(2.0)
    }
}

impl Default for EstimationCalibrator {
    fn default() -> Self {
        Self::new()
    }
}
use std::sync::OnceLock;

static CALIBRATOR: OnceLock<EstimationCalibrator> = OnceLock::new();
pub fn get_calibrator() -> &'static EstimationCalibrator {
    CALIBRATOR.get_or_init(EstimationCalibrator::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calibrator_basic() {
        let calibrator = EstimationCalibrator::new();
        assert!((calibrator.get_factor() - 2.0).abs() < 0.01);
        for _ in 0..10 {
            calibrator.record(100, 300);
        }
        let factor = calibrator.get_factor();
        assert!(factor > 2.0);
        assert!(factor < 3.5);
    }

    #[test]
    fn test_calibrate() {
        let calibrator = EstimationCalibrator::new();
        let calibrated = calibrator.calibrate(100);
        assert_eq!(calibrated, 200);
    }

    #[test]
    fn test_zero_handling() {
        let calibrator = EstimationCalibrator::new();
        calibrator.record(0, 100);
        calibrator.record(100, 0);

        assert_eq!(calibrator.sample_count.load(Ordering::Relaxed), 0);
    }
}
