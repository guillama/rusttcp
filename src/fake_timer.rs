use std::time::Duration;

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Timer {
    init: u64,
    millisecs: u64,
}

impl Timer {
    pub fn now() -> Self {
        Timer {
            ..Default::default()
        }
    }

    pub fn add_millisecs(&mut self, value: u64) {
        self.millisecs += value;
    }

    pub fn reset(&mut self) {
        self.millisecs = 0;
    }

    pub fn expired(&self) -> Duration {
        Duration::from_millis(self.millisecs - self.init)
    }
}
