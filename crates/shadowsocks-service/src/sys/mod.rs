use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(all(unix, not(target_os = "android")))] {
        mod unix;
        #[allow(unused_imports)]
        pub use self::unix::*;
    }

}
