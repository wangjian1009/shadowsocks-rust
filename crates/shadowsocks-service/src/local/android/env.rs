use std::fs;
use std::io;
use std::path::PathBuf;

fn get_cmd() -> io::Result<String> {
    let content = fs::read_to_string("/proc/self/cmdline")?;

    for s in content.split("\0") {
        return Ok(s.to_owned());
    }

    Ok(content)
}

pub fn get_apk_path() -> io::Result<String> {
    let cmd = get_cmd()?;

    let mut apk = PathBuf::from(cmd.clone());

    loop {
        if apk.ends_with("lib") {
            apk.pop();
            apk.push(&"base.apk");
            return Ok(apk.to_str().unwrap().to_string());
        } else {
            if !apk.pop() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("can`t rebuild cmd to apk, cmd={}", cmd),
                ));
            }
        }
    }
}
