use bytes::BufMut;

#[inline]
pub fn xorfwd_with_pending(x: &mut [u8], sz: usize) {
    if sz <= 4 {
        return;
    }

    let xtra = 4 - sz % 4;

    if xtra != 4 {
        // 需要补充以后计算

        let xtra_sz = sz + xtra;
        assert!(xtra_sz % 4 == 0);

        if xtra_sz <= x.len() {
            // 补充以后的大小和当前缓存范围内，直接计算
            xorfwd(&mut x[..xtra_sz])
        } else {
            // 分两段计算，避免分配大的内存
            let block1_sz = xtra_sz - 4;
            assert!(block1_sz % 4 == 0);
            assert!(block1_sz < sz);
            assert!(block1_sz > 0);
            xorfwd(&mut x[..block1_sz]);

            let block2_sz = sz - block1_sz;
            assert!(block2_sz > 0);
            assert!(block2_sz < 4);

            assert!(block1_sz >= 4);
            let mut block2 = vec![0u8; 8];
            (&mut block2[..]).put_slice(&x[(block1_sz - 4)..sz]);
            xorfwd(&mut block2);
            (&mut x[block1_sz..sz]).put_slice(&block2[4..(4 + block2_sz)]);
        }
    } else {
        xorfwd(&mut x[..sz])
    }
}

#[inline]
pub fn xorbkd_with_pending(x: &mut [u8], sz: usize) {
    if sz <= 4 {
        return;
    }

    let xtra = 4 - sz % 4;

    if xtra != 4 {
        // 需要补充以后计算

        let xtra_sz = sz + xtra;
        assert!(xtra_sz % 4 == 0);

        if xtra_sz <= x.len() {
            // 补充以后的大小和当前缓存范围内，直接计算
            xorbkd(&mut x[..xtra_sz])
        } else {
            // 分两段计算，避免分配大的内存
            let block1_sz = xtra_sz - 4;
            assert!(block1_sz % 4 == 0);
            assert!(block1_sz < sz);
            assert!(block1_sz > 0);

            let block2_sz = sz - block1_sz;
            assert!(block2_sz > 0);
            assert!(block2_sz < 4);

            assert!(block1_sz >= 4);
            let mut block2 = vec![0u8; 8];
            (&mut block2[..]).put_slice(&x[(block1_sz - 4)..sz]);
            xorbkd(&mut block2);
            (&mut x[block1_sz..sz]).put_slice(&block2[4..(4 + block2_sz)]);

            xorbkd(&mut x[..block1_sz]);
        }
    } else {
        xorbkd(&mut x[..sz])
    }
}

#[inline]
pub fn xorfwd(x: &mut [u8]) {
    for i in 4..x.len() {
        x[i] ^= x[i - 4];
    }
}

#[inline]
pub fn xorbkd(x: &mut [u8]) {
    let mut i = x.len() - 1;
    while i >= 4 {
        x[i] ^= x[i - 4];
        i -= 1;
    }
}

#[cfg(test)]
mod test {
    use bytes::BufMut;

    use super::*;

    #[test]
    fn xorfwd_basic() {
        let mut buf = b"12345678".to_owned();
        xorfwd(&mut buf);
        xorbkd(&mut buf);

        assert_eq!(b"12345678", &buf[..]);
    }

    #[test]
    fn xorfwd_2block() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .is_test(true)
            .try_init();

        let input = b"1234567";

        let mut buf1 = [0u8; 7];
        (&mut buf1[0..]).put_slice(input);
        xorfwd_with_pending(&mut buf1, input.len());

        let mut buf2 = [0u8; 8];
        (&mut buf2[0..]).put_slice(input);
        xorfwd_with_pending(&mut buf2, input.len());

        assert_eq!(buf1[..input.len()], buf2[..input.len()]);
        assert_ne!(buf1[..input.len()], input[..]);
    }

    fn xor_rebuild(src: &[u8], cache_sz: usize) -> Vec<u8> {
        let data_len = src.len();
        let mut buf = vec![0; cache_sz];

        (&mut buf[..]).put_slice(src);
        xorfwd_with_pending(buf.as_mut_slice(), data_len);
        xorbkd_with_pending(buf.as_mut_slice(), data_len);

        let _ = buf.split_off(data_len);

        buf
    }

    #[test]
    fn ignore() {
        assert_eq!(b"", xor_rebuild(b"", 5).as_slice());
        assert_eq!(b"123", xor_rebuild(b"123", 4).as_slice());
        assert_eq!(b"1234", xor_rebuild(b"1234", 4).as_slice());
    }

    #[test]
    fn pending_inline() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .is_test(true)
            .try_init();

        assert_eq!(b"1234567", xor_rebuild(b"1234567", 8).as_slice());
    }

    #[test]
    fn pending_2block() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .is_test(true)
            .try_init();

        assert_eq!(b"1234567", xor_rebuild(b"1234567", 7).as_slice());
    }
}
