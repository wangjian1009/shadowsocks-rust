use cryptographic_message_syntax::SignedData;
use std::fs;
use std::io;
use std::io::prelude::*;
use std::ops::Index;

use super::{
    env::{get_apk_path, get_sdk_version_code, load_path_infos, PathEntryInfo},
    signed_data,
};

pub enum ValidateError {
    FindApkFail(io::Error),
    OpenApkFail(io::Error),
    UnzipApkFail(zip::result::ZipError),
    SignedDataLoadFail(io::Error),
    SignedDataNotFound,
    SignedDataDecodeFail(io::Error),
    SignedDataNoCert,
    CertCheckFailed,
    PathCheckFailed(Option<String>, io::Error),
}

impl std::fmt::Display for ValidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FindApkFail(..) => write!(f, "package not found"),
            Self::OpenApkFail(..) => write!(f, "package open fail"),
            Self::UnzipApkFail(..) => write!(f, "package unzip fail"),
            Self::SignedDataLoadFail(..) => write!(f, "signed data load fail"),
            Self::SignedDataNotFound => write!(f, "signed data not found"),
            Self::SignedDataDecodeFail(..) => write!(f, "signed data decode fail"),
            Self::SignedDataNoCert => write!(f, "signed data no cert"),
            Self::CertCheckFailed => write!(f, "cert check failed"),
            Self::PathCheckFailed(..) => write!(f, "path check failed"),
        }
    }
}

impl std::fmt::Debug for ValidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FindApkFail(e) => write!(f, "package not found({:?}", e),
            Self::OpenApkFail(e) => write!(f, "package open fail({:?}", e),
            Self::UnzipApkFail(e) => write!(f, "package unzip fail({:?})", e),
            Self::SignedDataLoadFail(e) => write!(f, "cert load fail({:?})", e),
            Self::SignedDataNotFound => write!(f, "cert not found"),
            Self::SignedDataDecodeFail(e) => write!(f, "cert decode fail({:?})", e),
            Self::SignedDataNoCert => write!(f, "signed data no cert"),
            Self::CertCheckFailed => write!(f, "cert check failed"),
            Self::PathCheckFailed(ef, e) => {
                if let Some(ef) = ef {
                    write!(f, "path {} check failed: {:?}", ef, e)
                } else {
                    write!(f, "path check failed: {:?}", e)
                }
            }
        }
    }
}

pub struct ValidateResult {
    pub apk_path: Option<String>,
    pub signed_data_file: Option<String>,
    pub signed_data: Option<SignedData>,
    pub sha1_fingerprint: Option<Vec<u8>>,
    pub error: Option<ValidateError>,
}

pub fn validate_sign() -> ValidateResult {
    let mut result = ValidateResult {
        apk_path: None,
        signed_data_file: None,
        signed_data: None,
        sha1_fingerprint: None,
        error: None,
    };

    match get_apk_path() {
        Ok(apk_path) => result.apk_path = Some(apk_path),
        Err(err) => {
            result.error = Some(ValidateError::FindApkFail(err));
            return result;
        }
    }

    let apk_path_infos = match load_path_infos(result.apk_path.as_ref().unwrap()) {
        Ok(path_infos) => path_infos,
        Err((path, err)) => {
            result.error = Some(ValidateError::PathCheckFailed(Some(path), err));
            return result;
        }
    };

    match apk_path_infos.len() {
        6 => match check_apk_path_match_expects(result.apk_path.as_ref().unwrap(), &apk_path_infos, &S_PERM_6) {
            Ok(()) => {}
            Err((f, e)) => {
                result.error = Some(ValidateError::PathCheckFailed(Some(f), e));
                return result;
            }
        },
        5 => {
            //__ANDROID_API_P__ 28
            if get_sdk_version_code() <= 28 {
                //sdk_version_code <= __ANDROID_API_P__
                match check_apk_path_match_expects(
                    result.apk_path.as_ref().unwrap(),
                    &apk_path_infos,
                    &S_PERM_5_9_BEFORE,
                ) {
                    Ok(()) => {}
                    Err((f, e)) => {
                        result.error = Some(ValidateError::PathCheckFailed(Some(f), e));
                        return result;
                    }
                }
            } else {
                match check_apk_path_match_expects(
                    result.apk_path.as_ref().unwrap(),
                    &apk_path_infos,
                    &S_PERM_5_10_AFTER,
                ) {
                    Ok(()) => {}
                    Err((f, e)) => {
                        result.error = Some(ValidateError::PathCheckFailed(Some(f), e));
                        return result;
                    }
                }
            }
        }
        _ => {
            result.error = Some(ValidateError::PathCheckFailed(
                Some(result.apk_path.as_ref().unwrap().to_owned()),
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("path level {} unknown", apk_path_infos.len()),
                ),
            ));
            return result;
        }
    }

    let apk_file = match fs::File::open(result.apk_path.as_ref().unwrap()) {
        Ok(apk_file) => apk_file,
        Err(err) => {
            result.error = Some(ValidateError::OpenApkFail(err));
            return result;
        }
    };

    let mut apk_archive = match zip::ZipArchive::new(apk_file) {
        Ok(apk_archive) => apk_archive,
        Err(err) => {
            result.error = Some(ValidateError::UnzipApkFail(err));
            return result;
        }
    };

    // 加载证书内容
    const TO_CHECK_CERTS: &[&'static str] = &["META-INF/BNDLTOOL.RSA", "META-INF/CERT.RSA"];
    let mut file_and_content = None;
    for f in TO_CHECK_CERTS {
        file_and_content = match load_file_content(&mut apk_archive, f) {
            Ok(content) => match content {
                Some(content) => Some((f, content)),
                None => None,
            },
            Err(err) => {
                result.error = Some(ValidateError::SignedDataLoadFail(err));
                return result;
            }
        };

        if file_and_content.is_some() {
            break;
        }
    }
    let content = match file_and_content {
        None => {
            result.error = Some(ValidateError::SignedDataNotFound);
            return result;
        }
        Some((file, context)) => {
            result.signed_data_file = Some(file.to_string());
            context
        }
    };

    match signed_data::load_signed_data(&content[..]) {
        Ok(signed_data) => result.signed_data = Some(signed_data),
        Err(err) => {
            result.error = Some(ValidateError::SignedDataDecodeFail(err));
            return result;
        }
    }

    result.sha1_fingerprint = signed_data::get_signed_data_sha1_fingerprint(result.signed_data.as_ref().unwrap());
    if result.sha1_fingerprint.is_none() {
        result.error = Some(ValidateError::SignedDataNoCert);
        return result;
    }

    if !check_sha1_fingerprint(&result.sha1_fingerprint.as_ref().unwrap()[..]) {
        result.error = Some(ValidateError::CertCheckFailed);
        return result;
    }

    result
}

fn load_file_content(archive: &mut zip::ZipArchive<fs::File>, fname: &str) -> io::Result<Option<Vec<u8>>> {
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).unwrap();
        if let Some(path) = file.enclosed_name() {
            if path.to_str() == Some(fname) {
                let mut contents = Vec::new();
                file.read_to_end(&mut contents)?;
                return Ok(Some(contents));
            }
        };
    }

    Ok(None)
}

const S_PERM_5_10_AFTER: [PathEntryInfo; 5] = [
    PathEntryInfo {
        uid: 0,
        gid: 0,
        perm_u: 7,
        perm_g: 5,
        perm_o: 5,
    },
    PathEntryInfo {
        uid: 1000,
        gid: 1000,
        perm_u: 7,
        perm_g: 7,
        perm_o: 1,
    },
    PathEntryInfo {
        uid: 1000,
        gid: 1000,
        perm_u: 7,
        perm_g: 7,
        perm_o: 1,
    },
    PathEntryInfo {
        uid: 1000,
        gid: 1000,
        perm_u: 7,
        perm_g: 7,
        perm_o: 5,
    },
    PathEntryInfo {
        uid: 1000,
        gid: 1000,
        perm_u: 6,
        perm_g: 4,
        perm_o: 4,
    },
];

const S_PERM_5_9_BEFORE: [PathEntryInfo; 5] = [
    PathEntryInfo {
        uid: 0,
        gid: 0,
        perm_u: 7,
        perm_g: 5,
        perm_o: 5,
    },
    PathEntryInfo {
        uid: 1000,
        gid: 1000,
        perm_u: 7,
        perm_g: 7,
        perm_o: 1,
    },
    PathEntryInfo {
        uid: 1000,
        gid: 1000,
        perm_u: 7,
        perm_g: 7,
        perm_o: 1,
    },
    PathEntryInfo {
        uid: 1000,
        gid: 1000,
        perm_u: 7,
        perm_g: 5,
        perm_o: 5,
    },
    PathEntryInfo {
        uid: 1000,
        gid: 1000,
        perm_u: 6,
        perm_g: 4,
        perm_o: 4,
    },
];

const S_PERM_6: [PathEntryInfo; 6] = [
    PathEntryInfo {
        uid: 0,
        gid: 0,
        perm_u: 7,
        perm_g: 5,
        perm_o: 5,
    },
    PathEntryInfo {
        uid: 1000,
        gid: 1000,
        perm_u: 7,
        perm_g: 7,
        perm_o: 1,
    },
    PathEntryInfo {
        uid: 1000,
        gid: 1000,
        perm_u: 7,
        perm_g: 7,
        perm_o: 1,
    },
    PathEntryInfo {
        uid: 1000,
        gid: 1000,
        perm_u: 7,
        perm_g: 7,
        perm_o: 5,
    },
    PathEntryInfo {
        uid: 1000,
        gid: 1000,
        perm_u: 7,
        perm_g: 7,
        perm_o: 5,
    },
    PathEntryInfo {
        uid: 1000,
        gid: 1000,
        perm_u: 6,
        perm_g: 4,
        perm_o: 4,
    },
];

pub fn check_apk_path_match_expects(
    all_path: &str,
    path_infos: &Vec<PathEntryInfo>,
    expect: &[PathEntryInfo],
) -> std::result::Result<(), (String, io::Error)> {
    assert!(path_infos.len() == expect.len());

    for pos in 0..path_infos.len() {
        if path_infos.index(pos) != &expect[pos] {
            let all_path = std::path::Path::new(all_path);

            let mut left_path: Option<&std::path::Path> = Some(&all_path);
            for _j in 0..(path_infos.len() - pos - 1) {
                left_path = left_path.unwrap().parent();
            }

            return Err((
                left_path.unwrap().to_str().unwrap().to_owned(),
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("PathPermMismatch({} <=> {})", path_infos.index(pos), &expect[pos]),
                ),
            ));
        }
    }

    Ok(())
}

fn check_sha1_fingerprint(fingerprint: &[u8]) -> bool {
    let all_sha1_fingerprint = vec![
        // coolline debug
        vec![
            0x20, 0xF7, 0x71, 0x03, 0x8D, 0xAD, 0x67, 0xDD, 0xBD, 0x74, 0x62, 0xFD, 0x30, 0x0F, 0xB4, 0x0A, 0xFB, 0x10,
            0xD5, 0x5B,
        ],
        // coolline GP
        vec![
            0x9F, 0xD8, 0x04, 0x63, 0x35, 0xD8, 0x2F, 0x6F, 0x20, 0xF7, 0x57, 0x81, 0x31, 0xD9, 0x2E, 0xC3, 0x56, 0x78,
            0x56, 0xCF,
        ],
    ];

    for check in &all_sha1_fingerprint[..] {
        if check == fingerprint {
            return true;
        }
    }

    return false;
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_check_sha1_fingerprint() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init();
    }
}

// vec![
//     0x9F, 0xD8, 0x04, 0x63, 0x35, 0xD8, 0x2F, 0x6F, 0x20, 0xF7, 0x57, 0x81, 0x31, 0xD9, 0x2E, 0xC3, 0x56,
//     0x78, 0x56, 0xCF
// ],
