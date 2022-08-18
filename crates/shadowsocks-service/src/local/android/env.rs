use cfg_if::cfg_if;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

cfg_if! {
    if #[cfg(unix)] {
        use std::os::unix::fs::MetadataExt;
    }
}

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

#[derive(Debug, PartialEq)]
pub struct PathEntryInfo {
    pub uid: u32,
    pub gid: u32,
    pub perm_u: u8,
    pub perm_g: u8,
    pub perm_o: u8,
}

impl std::fmt::Display for PathEntryInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{},{},{},{},{}",
            self.uid, self.gid, self.perm_u, self.perm_g, self.perm_o
        )
    }
}

pub fn load_path_infos(path: &str) -> std::result::Result<Vec<PathEntryInfo>, (String, io::Error)> {
    let mut path_infos: Vec<PathEntryInfo> = Vec::new();

    let path = Path::new(path);

    let mut cur_path: Option<&Path> = Some(&path);
    while cur_path.is_some() {
        let path_state_info = match cur_path.unwrap().metadata() {
            #[cfg(unix)]
            Ok(meta) => {
                let mode = meta.mode();
                PathEntryInfo {
                    uid: meta.uid(),
                    gid: meta.gid(),
                    perm_u: ((mode & 0o700) >> 6) as u8,
                    perm_g: ((mode & 0o070) >> 3) as u8,
                    perm_o: (mode & 0o007) as u8,
                }
            }
            #[cfg(not(unix))]
            Ok(_meta) => PathEntryInfo {
                uid: 0,
                gid: 0,
                perm_u: 0,
                perm_g: 0,
                perm_o: 0,
            },
            Err(err) => return Err((cur_path.unwrap().to_str().unwrap().to_owned(), err)),
        };
        // log::error!("xxxxxxx: path: {:?}, info: {:?}", cur_path.unwrap(), path_state_info);

        path_infos.push(path_state_info);

        cur_path = cur_path.as_ref().unwrap().parent();
    }

    path_infos.reverse();

    Ok(path_infos)
}

cfg_if! {
    if #[cfg(target_os = "android")] {
        use std::ffi::CString;
        use std::os::raw;

        #[link(name = "android")]
        extern "C" {
            fn __system_property_get(name: *const raw::c_char, value: *mut raw::c_char) -> raw::c_int;
        }

        pub fn get_sdk_version_code() -> u32 {
            // 获取 SDK 版本号
            let mut sdk_version = vec![0u8; 128];
            let c_key = CString::new("ro.build.version.sdk").unwrap();
            unsafe {
                __system_property_get(c_key.as_ptr(), sdk_version.as_mut_ptr() as *mut raw::c_char);

                for n in 1..sdk_version.len() {
                    if sdk_version[n] == 0 {
                        sdk_version.truncate(n);
                        break;
                    }
                }
            }

            let sdk_version = CString::new(sdk_version).unwrap().into_string().unwrap();
            sdk_version.parse::<u32>().unwrap()
        }
    }
}

#[cfg(not(target_os = "android"))]
pub fn get_sdk_version_code() -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_path_infos() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init();

        let current_dir = std::env::current_dir().expect("read current dir success");

        let _dir_infos = load_path_infos(current_dir.to_str().unwrap());
    }
}
