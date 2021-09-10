pub use log;
use std::{ffi::CString, os::raw::c_char};

extern "C" {
    fn __apple_log(s: *const c_char);
}

pub struct AppleLogger {
    format: Box<dyn Fn(&log::Record) -> String + Sync + Send>,
}

pub struct LogBuilder {
    format: Box<dyn Fn(&log::Record) -> String + Sync + Send>,
}

pub fn init() -> Result<(), log::SetLoggerError> {
    AppleLogger::new().init()
}

impl AppleLogger {
    pub fn new() -> AppleLogger {
        LogBuilder::new().build()
    }

    pub fn init(self) -> Result<(), log::SetLoggerError> {
        let r = log::set_boxed_logger(Box::new(self));

        if r.is_ok() {
            log::set_max_level(log::LevelFilter::Trace);
        }

        r
    }
}

impl log::Log for AppleLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn flush(&self) {}

    fn log(&self, record: &log::Record) {
        if !log::Log::enabled(self, record.metadata()) {
            return;
        }

        let format = CString::new((self.format)(record)).unwrap();

        // let prio = match record.level() {
        //     LogLevel::Error => LogPriority::ERROR,
        //     LogLevel::Warn => LogPriority::WARN,
        //     LogLevel::Info => LogPriority::INFO,
        //     LogLevel::Debug => LogPriority::DEBUG,
        //     LogLevel::Trace => LogPriority::VERBOSE,
        // };

        unsafe {
            __apple_log(format.as_ptr());
        }
    }
}

impl LogBuilder {
    pub fn new() -> LogBuilder {
        LogBuilder {
            format: Box::new(|record: &log::Record| {
                format!("{}: {}", record.module_path().unwrap_or("unknown"), record.args())
            }),
        }
    }

    pub fn format<F: 'static>(&mut self, format: F) -> &mut Self
    where
        F: Fn(&log::Record) -> String + Sync + Send,
    {
        self.format = Box::new(format);
        self
    }

    pub fn init(self) -> Result<(), log::SetLoggerError> {
        self.build().init()
    }

    pub fn build(self) -> AppleLogger {
        AppleLogger { format: self.format }
    }
}
