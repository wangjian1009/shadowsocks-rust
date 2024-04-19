use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(all(unix, not(target_os = "android")))] {
        mod unix;
        pub use self::unix::*;
    }

}
