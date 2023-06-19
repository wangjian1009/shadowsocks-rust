use clap::Command;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::slice;

use crate::service::url;

#[no_mangle]
pub extern "C" fn lib_url_run(argc: c_int, argv: *const *const c_char) {
    let argv: &[*const c_char] = unsafe { slice::from_raw_parts(argv, argc as usize) };

    let argv: Vec<String> = argv
        .iter()
        .map(|s| unsafe { CStr::from_ptr(*s).to_string_lossy().to_owned().into_owned() })
        .collect();

    let mut app = Command::new("shadowsocks url")
        .version(crate::VERSION)
        .about("A fast tunnel proxy that helps you bypass firewalls. (https://shadowsocks.org)");
    app = url::define_command_line_options(app);

    let matches = match app.try_get_matches_from(argv) {
        Ok(m) => m,
        Err(_err) => {
            return;
        }
    };

    url::main(
        &matches,
        #[cfg(feature = "logging")]
        false,
    );
}
