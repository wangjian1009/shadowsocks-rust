use cryptographic_message_syntax::SignedData;
use std::fs;
use std::io;
use std::io::prelude::*;
use std::ops::Index;

use super::{
    env::{apk_path_prefix, get_apk_path, get_sdk_version_code, load_path_infos, PathEntryInfo},
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
    CertNotFound,
    CertDuplicate(String, String),
    CertCheckFailed,
    PathCheckFailed(Option<String>, io::Error),
}

impl ValidateError {
    pub fn code(&self) -> u16 {
        match self {
            Self::FindApkFail(..) => 1,
            Self::OpenApkFail(..) => 2,
            Self::UnzipApkFail(..) => 3,
            Self::SignedDataLoadFail(..) => 4,
            Self::SignedDataNotFound => 5,
            Self::SignedDataDecodeFail(..) => 6,
            Self::SignedDataNoCert => 7,
            Self::CertNotFound => 8,
            Self::CertDuplicate(..) => 9,
            Self::CertCheckFailed => 10,
            Self::PathCheckFailed(..) => 11,
        }
    }
}

impl std::fmt::Display for ValidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "E{:4}", self.code())
    }
}

impl std::fmt::Debug for ValidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FindApkFail(e) => write!(f, "E{:4}({:?})", self.code(), e),
            Self::OpenApkFail(e) => write!(f, "E{:4}({:?})", self.code(), e),
            Self::UnzipApkFail(e) => write!(f, "E{:4}({:?})", self.code(), e),
            Self::SignedDataLoadFail(e) => write!(f, "E{:4}({:?})", self.code(), e),
            Self::SignedDataNotFound => write!(f, "E{:4}", self.code()),
            Self::SignedDataDecodeFail(e) => write!(f, "E{:4}({:?})", self.code(), e),
            Self::SignedDataNoCert => write!(f, "E{:4}", self.code()),
            Self::CertNotFound => write!(f, "E{:4}", self.code()),
            Self::CertDuplicate(a, b) => write!(f, "E{:4}({},{})", self.code(), a, b),
            Self::CertCheckFailed => write!(f, "E{:4}", self.code()),
            Self::PathCheckFailed(ef, e) => {
                if let Some(ef) = ef {
                    write!(f, "E{:4}({},{:?})", self.code(), ef, e)
                } else {
                    write!(f, "E{:4}({:?})", self.code(), e)
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
    pub path_error: Option<ValidateError>,
}

pub fn validate_sign() -> ValidateResult {
    let mut result = ValidateResult {
        apk_path: None,
        signed_data_file: None,
        signed_data: None,
        sha1_fingerprint: None,
        error: None,
        path_error: None,
    };

    // 获取apk路径
    match get_apk_path() {
        Ok(apk_path) => result.apk_path = Some(apk_path),
        Err(err) => {
            result.error = Some(ValidateError::FindApkFail(err));
            return result;
        }
    }

    // 验证apk路径权限
    validate_sign_apk_path(&mut result);
    if result.error.is_some() {
        return result;
    }

    // 打开apk文件
    let apk_file = match fs::File::open(result.apk_path.as_ref().unwrap()) {
        Ok(apk_file) => apk_file,
        Err(err) => {
            result.error = Some(ValidateError::OpenApkFail(err));
            return result;
        }
    };

    // 加载apk内容
    let mut apk_archive = match zip::ZipArchive::new(apk_file) {
        Ok(apk_archive) => apk_archive,
        Err(err) => {
            result.error = Some(ValidateError::UnzipApkFail(err));
            return result;
        }
    };

    // 找到证书路径
    match search_cert_file(&apk_archive, &mut result) {
        Some(f) => {
            result.signed_data_file = Some(f);
        }
        None => {
            assert!(result.error.is_some());
            return result;
        }
    };

    // 加载证书内容
    let content = match load_file_content(&mut apk_archive, result.signed_data_file.as_ref().unwrap()) {
        Ok(content) => match content {
            None => {
                result.error = Some(ValidateError::SignedDataNotFound);
                return result;
            }
            Some(context) => context,
        },
        Err(err) => {
            result.error = Some(ValidateError::SignedDataLoadFail(err));
            return result;
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

fn validate_sign_apk_path(result: &mut ValidateResult) {
    match get_apk_path() {
        Ok(apk_path) => result.apk_path = Some(apk_path),
        Err(err) => {
            result.error = Some(ValidateError::FindApkFail(err));
            return;
        }
    }

    let path = result.apk_path.as_ref().unwrap();
    if std::path::Path::new(path.as_str()).starts_with(apk_path_prefix().as_str()) {
        result.error = Some(ValidateError::PathCheckFailed(
            Some(path.to_owned()),
            io::ErrorKind::WouldBlock.into(),
        ));
    }

    let apk_path_infos = match load_path_infos(path) {
        Ok(path_infos) => path_infos,
        Err((path, err)) => {
            result.error = Some(ValidateError::PathCheckFailed(Some(path), err));
            return;
        }
    };

    result.path_error = match apk_path_infos.len() {
        6 => match check_apk_path_match_expects(result.apk_path.as_ref().unwrap(), &apk_path_infos, &S_PERM_6) {
            Ok(()) => None,
            Err((f, e)) => Some(ValidateError::PathCheckFailed(Some(f), e)),
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
                    Ok(()) => None,
                    Err((f, e)) => Some(ValidateError::PathCheckFailed(Some(f), e)),
                }
            } else {
                match check_apk_path_match_expects(
                    result.apk_path.as_ref().unwrap(),
                    &apk_path_infos,
                    &S_PERM_5_10_AFTER,
                ) {
                    Ok(()) => None,
                    Err((f, e)) => Some(ValidateError::PathCheckFailed(Some(f), e)),
                }
            }
        }
        _ => Some(ValidateError::PathCheckFailed(
            Some(path.to_owned()),
            io::Error::new(io::ErrorKind::Other, format!("{}", apk_path_infos.len())),
        )),
    };
}

const S_SEED: [u8; 8] = [0x33, 0x34, 0x52, 0x58, 0x11, 0x73, 0x94, 0x38];
const fn const_string_encode<const N: usize>(mut input: [u8; N]) -> [u8; N] {
    if 0 < N {
        input[0] ^= S_SEED[0 % S_SEED.len()];
    }

    if 1 < N {
        input[1] ^= S_SEED[1 % S_SEED.len()];
    }

    if 2 < N {
        input[2] ^= S_SEED[2 % S_SEED.len()];
    }

    if 3 < N {
        input[3] ^= S_SEED[3 % S_SEED.len()];
    }

    if 4 < N {
        input[4] ^= S_SEED[4 % S_SEED.len()];
    }

    if 5 < N {
        input[5] ^= S_SEED[5 % S_SEED.len()];
    }

    if 6 < N {
        input[6] ^= S_SEED[6 % S_SEED.len()];
    }

    if 7 < N {
        input[7] ^= S_SEED[7 % S_SEED.len()];
    }

    if 8 < N {
        input[8] ^= S_SEED[8 % S_SEED.len()];
    }

    if 9 < N {
        input[9] ^= S_SEED[9 % S_SEED.len()];
    }

    if 10 < N {
        input[10] ^= S_SEED[10 % S_SEED.len()];
    }

    assert!(N < 10);
    input
}

// meta-inf/
const PATH_PREFIX: [u8; 9] = const_string_encode([0x6D, 0x65, 0x74, 0x61, 0x2D, 0x69, 0x6E, 0x66, 0x2F]);
// .rsa
const PATH_SUFFIX: [u8; 4] = const_string_encode([0x2E, 0x72, 0x73, 0x61]);

#[inline]
fn check_file_match(path_name: &str) -> bool {
    // meta-inf/a.rsa
    if path_name.len() < 14 {
        return false;
    }

    let path_name = path_name.to_lowercase();

    let mut prefix = [0u8; 9];
    prefix.copy_from_slice(&path_name.as_bytes()[..9]);
    if const_string_encode(prefix) != PATH_PREFIX {
        return false;
    }

    let mut suffix = [0u8; 4];
    suffix.copy_from_slice(&path_name.as_bytes()[(path_name.len() - 4)..]);
    if const_string_encode(suffix) != PATH_SUFFIX {
        return false;
    }

    true
}

fn search_cert_file(apk_archive: &zip::ZipArchive<fs::File>, result: &mut ValidateResult) -> Option<String> {
    let mut found_path = None;

    for path_name in apk_archive.file_names() {
        if check_file_match(path_name) {
            if found_path.is_none() {
                found_path = Some(path_name.to_owned());
            } else {
                result.error = Some(ValidateError::CertDuplicate(found_path.unwrap(), path_name.to_owned()));
                return None;
            }
        }
    }

    if found_path.is_none() {
        result.error = Some(ValidateError::CertNotFound);
        return None;
    }

    Some(found_path.unwrap())
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

            let mut left_path: Option<&std::path::Path> = Some(all_path);
            for _j in 0..(path_infos.len() - pos - 1) {
                left_path = left_path.unwrap().parent();
            }

            return Err((
                left_path.unwrap().to_str().unwrap().to_owned(),
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("{} <=> {}", path_infos.index(pos), &expect[pos]),
                ),
            ));
        }
    }

    Ok(())
}

const FP_BLOB_COUNT: usize = 4;
const FP_BLOBS: [u8; 20 * FP_BLOB_COUNT] = [
    231, 48, 182, 196, 74, 106, 160, 26, 122, 179, 165, 58, 247, 200, 115, 205, 60, 215, 18, 156, 88, 31, 195, 164,
    242, 31, 232, 168, 231, 48, 144, 70, 246, 30, 233, 4, 145, 191, 145, 8, 102, 117, 143, 202, 243, 48, 169, 122, 178,
    102, 88, 30, 153, 54, 72, 147, 121, 14, 71, 201, 102, 117, 143, 202, 243, 48, 169, 122, 178, 102, 88, 30, 153, 54,
    72, 147, 121, 14, 71, 201,
];

fn check_sha1_fingerprint(fingerprint: &[u8]) -> bool {
    for i in 0..FP_BLOB_COUNT {
        let mut found = true;

        for j in 0..fingerprint.len() {
            let cp = i * 20 + j;
            if cp >= FP_BLOBS.len() {
                found = false;
                break;
            }

            if fingerprint[j] ^ 0xC7 != FP_BLOBS[cp] {
                found = false;
                break;
            }
        }

        if found {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_sha1_fingerprint() {}

    #[test]
    #[traced_test]
    fn file_match_1() {
        assert_eq!(check_file_match("aa"), false);
        assert_eq!(check_file_match("MeTA-INf/CeRT.RsA"), true);
        assert_eq!(check_file_match("MeTA-INf/CeRT.RsB"), false);
    }

    // coolline debug
    const FP_COOLLINE_DEBUG: [u8; 20] = [
        0x20, 0xF7, 0x71, 0x03, 0x8D, 0xAD, 0x67, 0xDD, 0xBD, 0x74, 0x62, 0xFD, 0x30, 0x0F, 0xB4, 0x0A, 0xFB, 0x10,
        0xD5, 0x5B,
    ];

    // coolline GP
    const FP_COOLLINE_GP: [u8; 20] = [
        0x9F, 0xD8, 0x04, 0x63, 0x35, 0xD8, 0x2F, 0x6F, 0x20, 0xF7, 0x57, 0x81, 0x31, 0xD9, 0x2E, 0xC3, 0x56, 0x78,
        0x56, 0xCF,
    ];

    // Now debug
    const FP_NOW_DEBUG: [u8; 20] = [
        0xA1, 0xB2, 0x48, 0x0D, 0x34, 0xF7, 0x6E, 0xBD, 0x75, 0xA1, 0x9F, 0xD9, 0x5E, 0xF1, 0x8F, 0x54, 0xBE, 0xC9,
        0x80, 0x0E,
    ];

    // Now GP
    const FP_NOW_GP: [u8; 20] = [
        0xA1, 0xB2, 0x48, 0x0D, 0x34, 0xF7, 0x6E, 0xBD, 0x75, 0xA1, 0x9F, 0xD9, 0x5E, 0xF1, 0x8F, 0x54, 0xBE, 0xC9,
        0x80, 0x0E,
    ];

    fn build_fp_blob(fps: &[&[u8; 20]]) -> Vec<u8> {
        let mut buf = Vec::<u8>::new();
        buf.resize(fps.len() * 20, 0);

        for i in 0..fps.len() {
            let fp = fps[i];

            for j in 0..fp.len() {
                buf[i * 20 + j] = fp[j] ^ 0xC7;
            }
        }

        buf
    }

    #[test]
    #[traced_test]
    fn test_fp_validate_1() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&FP_BLOBS);

        assert_eq!(
            blob,
            build_fp_blob(&[&FP_COOLLINE_DEBUG, &FP_COOLLINE_GP, &FP_NOW_DEBUG, &FP_NOW_GP])
        );
        assert_eq!(check_sha1_fingerprint(&FP_COOLLINE_DEBUG), true);
        assert_eq!(check_sha1_fingerprint(&FP_COOLLINE_GP), true);
        assert_eq!(check_sha1_fingerprint(&FP_NOW_DEBUG), true);
        assert_eq!(check_sha1_fingerprint(&FP_NOW_GP), true);
    }
}
