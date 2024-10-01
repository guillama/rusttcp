use std::time::Duration;
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timer {
    sys_time: SystemTime,
}

impl Timer {
    pub fn new() -> Self {
        Timer {
            sys_time: SystemTime::UNIX_EPOCH,
        }
    }

    pub fn reset(&mut self) {
        self.sys_time = SystemTime::now();
    }

    pub fn expired(&self) -> Duration {
        self.sys_time.elapsed().unwrap()
    }
}

impl Default for Timer {
    fn default() -> Self {
        Timer {
            sys_time: SystemTime::UNIX_EPOCH,
        }
    }
}
