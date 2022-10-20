use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

// fn parse_package_name(path: &str) -> &str {
//     let parts: Vec<&str> = path.split("/").collect();
//     if parts.len() < 5 {
//         panic!("path {} too shot", path);
//     }
//     return parts[4];
// }

pub fn decrypt(enc_password: &str) -> Result<String, String> {
    let key = getkey()?;
    let iv: [u8; 16] = [
        0xae, 0x80, 0xed, 0xcb, 0x37, 0xc2, 0x70, 0x33, 0x21, 0xb3, 0x31, 0x07, 0xcf, 0x35, 0x88, 0xc3,
    ];

    let enc_password = match base64::decode(enc_password) {
        Ok(r) => r,
        Err(code) => {
            return Err(String::from(format!("{:?}", code)));
        }
    };
    let decrypt_password = aes256_cbc_decrypt(enc_password.as_ref(), &key, &iv)?;

    return match String::from_utf8(decrypt_password) {
        Ok(result) => Ok(result),
        Err(code) => Err(String::from(format!("{:?}", code))),
    };
}

fn getkey() -> Result<Vec<u8>, String> {
    let iv: [u8; 16] = [1; 16];
    let key: [u8; 32] = [
        0x6E, 0x41, 0x79, 0x76, 0x26, 0x2F, 0x5B, 0x31, 0x26, 0x5D, 0x44, 0x4E, 0x73, 0x48, 0x63, 0x44, 0x30, 0x33,
        0x2E, 0x52, 0x62, 0x5D, 0x69, 0x65, 0x35, 0x78, 0x50, 0x43, 0x46, 0x28, 0x2C, 0x44,
    ];

    // let aa  = base64::decode("D6gGZEI40uetWdBOBe+wrrxy2UiMxF6G0Y9YNRrETuKIE7B7oJ3uGFyTwGZTrYJd");
    // println!("xxx: password: {:?}", aa);

    let mut final_result = Vec::<u8>::new();

    final_result.extend_from_slice(&[16, 169, 7, 101]);
    final_result.extend_from_slice(&[67, 57, 211, 232]);
    final_result.extend_from_slice(&[174, 90, 209, 79]);
    final_result.extend_from_slice(&[6, 240, 177, 175]);
    final_result.extend_from_slice(&[189, 115, 218, 73]);
    final_result.extend_from_slice(&[141, 197, 95, 135]);
    final_result.extend_from_slice(&[210, 144, 89, 54]);
    final_result.extend_from_slice(&[27, 197, 79, 227]);
    final_result.extend_from_slice(&[137, 20, 177, 124]);
    final_result.extend_from_slice(&[161, 158, 239, 25]);
    final_result.extend_from_slice(&[93, 148, 193, 103]);
    final_result.extend_from_slice(&[84, 174, 131, 94]);

    let b: Vec<u8> = final_result.iter().map(|&i| i - 1).collect();
    aes256_cbc_decrypt(&b, &key, &iv)
}

fn aes256_cbc_decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8; 16]) -> Result<Vec<u8>, String> {
    let cipher =
        Aes256Cbc::new_from_slices(&key, iv).map_err(|e| format!("aes256_cbc_decrypt: cipher create iv fail {}", e))?;

    let plaintext = cipher
        .decrypt_vec(encrypted_data)
        .map_err(|e| format!("aes256_cbc_decrypt: decrypt fail {}", e))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use tokio_test::assert_ok;

    use super::*;

    #[test]
    fn decrypt_password_works() {
        let encryped_passwd = encrypt_password("*!hvk9^4baX#Y%Ja");
        let decrypt_passwd = decrypt(&encryped_passwd).unwrap();
        // println!("xxxx: hexkey: {}", hex::encode(getkey().to_vec()));
        // println!("xxxx: encryped_passwd: {}", encryped_passwd);
        assert_eq!(decrypt_passwd, "*!hvk9^4baX#Y%Ja");
    }

    #[test]
    fn decrypt_password_origin() {
        assert_eq!(
            decrypt("N35GLo6e1JXk8HEjABg54Wtyn4pvyApBAwjvBKjN3Bo=").unwrap(),
            "*!hvk9^4baX#Y%Ja"
        );
    }

    #[test]
    fn gen_password_password() {
        let iv: [u8; 16] = [1; 16];
        let key: [u8; 32] = [
            0x6E, 0x41, 0x79, 0x76, 0x26, 0x2F, 0x5B, 0x31, 0x26, 0x5D, 0x44, 0x4E, 0x73, 0x48, 0x63, 0x44, 0x30, 0x33,
            0x2E, 0x52, 0x62, 0x5D, 0x69, 0x65, 0x35, 0x78, 0x50, 0x43, 0x46, 0x28, 0x2C, 0x44,
        ];

        let key_str = "nAyv&/[1&]DNsHcD03.Rb]ie5xPCF(,D";
        assert_eq!(String::from_utf8(Vec::<u8>::from(key)).unwrap(), key_str);

        let origin_key = "3,B]6e9Lnm2X(92)/Y_Mx#hjx-F-MvxD";
        let encrypt_password = aes256_cbc_encrypt(origin_key.as_bytes(), &key, &iv);

        assert_eq!(
            assert_ok!(aes256_cbc_decrypt(&encrypt_password, &key, &iv)),
            "3,B]6e9Lnm2X(92)/Y_Mx#hjx-F-MvxD".as_bytes()
        );
    }

    #[test]
    fn getkey_work() {
        assert_eq!(
            assert_ok!(String::from_utf8(assert_ok!(getkey()))),
            String::from("3,B]6e9Lnm2X(92)/Y_Mx#hjx-F-MvxD")
        );
    }

    fn encrypt_password(origin_password: &str) -> String {
        let key = assert_ok!(getkey());
        // let iv = md5(pkg);
        let iv: [u8; 16] = [
            0xae, 0x80, 0xed, 0xcb, 0x37, 0xc2, 0x70, 0x33, 0x21, 0xb3, 0x31, 0x07, 0xcf, 0x35, 0x88, 0xc3,
        ];

        let encrypt_password = aes256_cbc_encrypt(origin_password.as_bytes(), &key, &iv);
        base64::encode(encrypt_password)
    }

    fn aes256_cbc_encrypt(data: &[u8], key: &[u8], iv: &[u8; 16]) -> Vec<u8> {
        let cipher = Aes256Cbc::new_from_slices(&key, iv).unwrap();
        let encrypted_data = cipher.encrypt_vec(data);
        encrypted_data
    }
}
